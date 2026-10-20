//! Adaptadores SQS de las fuentes de entrada del servicio (tarea MSG-NM-02):
//! [`SqsScanRequestSource`] implementa [`ScanRequestSource`] y
//! [`SqsScanCancellationSource`] implementa [`ScanCancellationSource`] sobre
//! `aws-sdk-sqs`. El resto del servicio (`pipeline`) no conoce SQS.
//!
//! Decisiones de diseño:
//!
//! - **Long polling**: `ReceiveMessage` con `WaitTimeSeconds = 20`. Las
//!   solicitudes se reciben de a **una** (`MaxNumberOfMessages = 1`): cada
//!   recepción inicia a lo sumo un escaneo, así un mensaje no espera detrás de
//!   otro mientras corre su visibilidad. Las cancelaciones se reciben en lotes
//!   de hasta 10 y se bufferizan (aplicarlas es en-proceso y rápido).
//! - **Borrado tras manejar** (decisión del usuario, 2026-10-19, igual que el
//!   gateway): una solicitud válida se entrega con un [`Acknowledger`]
//!   ([`SqsAcknowledger`]) que ejecuta `DeleteMessage`. El pipeline lo invoca
//!   solo cuando el escaneo terminó **y** su desenlace terminal se publicó. Si
//!   el proceso muere antes, SQS reentrega el mensaje al vencer el
//!   `VisibilityTimeout` (fijo, lo establece Terraform: no hay
//!   `ChangeMessageVisibility`) y, tras 3 recepciones, la `RedrivePolicy` de la
//!   cola lo mueve a la DLQ.
//! - **Cancelaciones**: la fuente borra una cancelación al **pedir la
//!   siguiente**, es decir, después de que el pipeline la aplicó (el bucle de
//!   cancelaciones aplica y vuelve a llamar). Un borrado fallido solo se
//!   registra: aplicar una cancelación es idempotente.
//! - **Malformados**: paridad con el `nack(requeue=false)` de AMQP. Se reenvía
//!   el cuerpo original a la DLQ con un `SendMessage` explícito (conservando
//!   los atributos del mensaje) y luego se borra de la cola origen. Si el envío
//!   a la DLQ falla **no** se borra: lo resuelve el redrive. En ambos casos la
//!   fuente devuelve `Err(MalformedPayload | InvalidSchema)`, que el pipeline
//!   registra y no trata como fatal.
//! - **Errores de recepción**: nunca llegan al pipeline como
//!   [`ConsumeError::Transport`] (el pipeline lo trata como fatal y detendría el
//!   consumo). El adaptador reintenta con backoff exponencial de 1 s hasta 30 s
//!   (reemplaza el bucle de reconexión de AMQP).
//!
//! # Seguridad
//!
//! Los cuerpos de las solicitudes transportan `ssh_credentials_ref`. Este
//! módulo nunca registra el cuerpo: solo el largo, el `correlation_id` de los
//! mensajes válidos y los errores (ya redactados) de `serde`. Las credenciales
//! de AWS salen de la cadena de proveedores por defecto (rol de la tarea ECS).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_sdk_sqs::error::DisplayErrorContext;
use aws_sdk_sqs::types::Message;
use aws_sdk_sqs::Client;

use crate::domain::ScanCancellation;
use crate::messaging::consumer::{
    log_cancellation_received, log_request_received, parse_scan_cancellation, parse_scan_request,
    AckError, Acknowledger, ConsumeError, IncomingScanRequest, ScanCancellationSource,
    ScanRequestSource,
};

/// Espera máxima del long polling de `ReceiveMessage`, en segundos.
const WAIT_TIME_SECONDS: i32 = 20;
/// Mensajes por recepción de solicitudes: uno por escaneo.
const REQUEST_BATCH: i32 = 1;
/// Mensajes por recepción de cancelaciones (tope de SQS).
const CANCELLATION_BATCH: i32 = 10;
/// Primer backoff tras un error de recepción.
const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
/// Tope del backoff exponencial.
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Siguiente espera del backoff: el doble, con tope en `max`.
fn next_backoff(current: Duration, max: Duration) -> Duration {
    (current * 2).min(max)
}

/// Construye un cliente SQS con la cadena de credenciales por defecto de AWS,
/// la `region` indicada y, opcionalmente, un `endpoint_url` (solo LocalStack).
async fn default_client(region: &str, endpoint_url: Option<&str>) -> Client {
    let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(region.to_owned()));
    if let Some(url) = endpoint_url {
        loader = loader.endpoint_url(url);
    }
    Client::new(&loader.load().await)
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// [`Acknowledger`] de SQS: borra el mensaje de su cola con `DeleteMessage`.
///
/// Su `Debug` no imprime el receipt handle.
#[derive(Clone)]
pub struct SqsAcknowledger {
    client: Client,
    queue_url: String,
    receipt_handle: String,
}

impl std::fmt::Debug for SqsAcknowledger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqsAcknowledger")
            .field("queue_url", &self.queue_url)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl Acknowledger for SqsAcknowledger {
    async fn ack(&self) -> Result<(), AckError> {
        delete_message(&self.client, &self.queue_url, &self.receipt_handle).await
    }
}

async fn delete_message(
    client: &Client,
    queue_url: &str,
    receipt_handle: &str,
) -> Result<(), AckError> {
    client
        .delete_message()
        .queue_url(queue_url)
        .receipt_handle(receipt_handle)
        .send()
        .await
        .map(|_| ())
        .map_err(|source| AckError {
            queue: queue_url.to_owned(),
            detail: DisplayErrorContext(&source).to_string(),
            source: Box::new(source),
        })
}

/// Lógica común de recepción: long poll con backoff, buffer de lote y manejo
/// de malformados hacia la DLQ.
struct SqsQueue {
    client: Client,
    queue_url: String,
    dlq_url: String,
    batch: i32,
    backoff_initial: Duration,
    backoff_max: Duration,
    buffer: Mutex<VecDeque<Message>>,
}

impl SqsQueue {
    fn new(client: Client, queue_url: String, dlq_url: String, batch: i32) -> Self {
        Self {
            client,
            queue_url,
            dlq_url,
            batch,
            backoff_initial: BACKOFF_INITIAL,
            backoff_max: BACKOFF_MAX,
            buffer: Mutex::new(VecDeque::new()),
        }
    }

    /// Devuelve el siguiente mensaje (del buffer o de un long poll nuevo),
    /// junto con su receipt handle. Reintenta con backoff exponencial ante
    /// errores de recepción; nunca devuelve error. Los mensajes sin receipt
    /// handle se descartan de la iteración (no se pueden borrar).
    async fn next_message(&self) -> (Message, String) {
        let mut backoff = self.backoff_initial;
        loop {
            let buffered = lock(&self.buffer).pop_front();
            if let Some(message) = buffered {
                match message.receipt_handle().map(str::to_owned) {
                    Some(handle) => return (message, handle),
                    None => {
                        tracing::error!("mensaje SQS sin receipt handle descartado");
                        continue;
                    }
                }
            }

            let received = self
                .client
                .receive_message()
                .queue_url(&self.queue_url)
                .wait_time_seconds(WAIT_TIME_SECONDS)
                .max_number_of_messages(self.batch)
                .message_attribute_names("All")
                .send()
                .await;
            match received {
                Ok(output) => {
                    backoff = self.backoff_initial;
                    lock(&self.buffer).extend(output.messages.unwrap_or_default());
                }
                Err(err) => {
                    tracing::error!(
                        error = %DisplayErrorContext(&err),
                        retry_in_ms = backoff.as_millis() as u64,
                        "error recibiendo de la cola SQS; se reintenta con backoff"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = next_backoff(backoff, self.backoff_max);
                }
            }
        }
    }

    /// Reenvía un mensaje malformado a la DLQ (cuerpo y atributos intactos) y
    /// recién entonces lo borra de la cola origen. Si el envío a la DLQ falla,
    /// no lo borra. Nunca registra el cuerpo.
    async fn dead_letter(&self, message: &Message, receipt_handle: &str) {
        let body = message.body().unwrap_or_default();
        let sent = self
            .client
            .send_message()
            .queue_url(&self.dlq_url)
            .message_body(body)
            .set_message_attributes(message.message_attributes().cloned())
            .send()
            .await;
        if let Err(err) = sent {
            tracing::error!(
                error = %DisplayErrorContext(&err),
                payload_len = body.len(),
                "no se pudo enviar un mensaje malformado a la DLQ; se deja en la cola"
            );
            return;
        }
        if let Err(err) = delete_message(&self.client, &self.queue_url, receipt_handle).await {
            tracing::error!(
                error = %err,
                "no se pudo borrar un mensaje malformado ya enviado a la DLQ"
            );
        }
    }
}

/// Fuente de solicitudes de escaneo sobre una cola SQS, con su DLQ para los
/// mensajes malformados. Ver la nota de diseño del módulo.
pub struct SqsScanRequestSource {
    queue: SqsQueue,
}

impl SqsScanRequestSource {
    /// Construye la fuente sobre un `client` ya configurado (los tests inyectan
    /// uno apuntando a LocalStack).
    pub fn from_client(client: Client, queue_url: String, dlq_url: String) -> Self {
        Self {
            queue: SqsQueue::new(client, queue_url, dlq_url, REQUEST_BATCH),
        }
    }

    /// Construye la fuente con la cadena de credenciales por defecto de AWS, la
    /// `region` indicada y, opcionalmente, un `endpoint_url` (solo LocalStack).
    pub async fn connect(
        region: &str,
        endpoint_url: Option<&str>,
        queue_url: String,
        dlq_url: String,
    ) -> Self {
        Self::from_client(
            default_client(region, endpoint_url).await,
            queue_url,
            dlq_url,
        )
    }

    /// Ajusta el backoff exponencial ante errores de recepción (por defecto de
    /// 1 s a 30 s). Útil para tests rápidos.
    #[must_use]
    pub fn with_backoff(mut self, initial: Duration, max: Duration) -> Self {
        self.queue.backoff_initial = initial;
        self.queue.backoff_max = max;
        self
    }
}

#[async_trait::async_trait]
impl ScanRequestSource for SqsScanRequestSource {
    /// Long poll hasta obtener un mensaje. Una solicitud válida se entrega con
    /// un [`SqsAcknowledger`] (no se borra hasta el `ack`); un cuerpo malformado
    /// va a la DLQ y se devuelve como `Err(MalformedPayload | InvalidSchema)`.
    /// Nunca devuelve `Ok(None)` ni `Err(Transport)`: los errores de recepción
    /// se reintentan dentro del adaptador.
    async fn next_request(&self) -> Result<Option<IncomingScanRequest>, ConsumeError> {
        let (message, receipt_handle) = self.queue.next_message().await;
        let body = message.body().unwrap_or_default();
        match parse_scan_request(body.as_bytes()) {
            Ok(request) => {
                log_request_received(&request);
                let ack = SqsAcknowledger {
                    client: self.queue.client.clone(),
                    queue_url: self.queue.queue_url.clone(),
                    receipt_handle,
                };
                Ok(Some(IncomingScanRequest::with_ack(request, Arc::new(ack))))
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    payload_len = body.len(),
                    "solicitud malformada en la cola SQS enviada a la DLQ"
                );
                self.queue.dead_letter(&message, &receipt_handle).await;
                Err(err)
            }
        }
    }
}

/// Fuente de cancelaciones sobre una cola SQS, con su DLQ para los mensajes
/// malformados. Ver la nota de diseño del módulo.
pub struct SqsScanCancellationSource {
    queue: SqsQueue,
    /// Receipt handle de la última cancelación entregada, pendiente de borrar
    /// cuando el pipeline pida la siguiente (o sea, ya la aplicó).
    delivered: Mutex<Option<String>>,
}

impl SqsScanCancellationSource {
    /// Construye la fuente sobre un `client` ya configurado.
    pub fn from_client(client: Client, queue_url: String, dlq_url: String) -> Self {
        Self {
            queue: SqsQueue::new(client, queue_url, dlq_url, CANCELLATION_BATCH),
            delivered: Mutex::new(None),
        }
    }

    /// Construye la fuente con la cadena de credenciales por defecto de AWS, la
    /// `region` indicada y, opcionalmente, un `endpoint_url` (solo LocalStack).
    pub async fn connect(
        region: &str,
        endpoint_url: Option<&str>,
        queue_url: String,
        dlq_url: String,
    ) -> Self {
        Self::from_client(
            default_client(region, endpoint_url).await,
            queue_url,
            dlq_url,
        )
    }

    /// Ajusta el backoff exponencial ante errores de recepción (por defecto de
    /// 1 s a 30 s).
    #[must_use]
    pub fn with_backoff(mut self, initial: Duration, max: Duration) -> Self {
        self.queue.backoff_initial = initial;
        self.queue.backoff_max = max;
        self
    }

    async fn delete_delivered(&self) {
        let handle = lock(&self.delivered).take();
        if let Some(handle) = handle {
            if let Err(err) =
                delete_message(&self.queue.client, &self.queue.queue_url, &handle).await
            {
                tracing::warn!(
                    error = %err,
                    "no se pudo borrar una cancelación ya aplicada; SQS la reentregará (idempotente)"
                );
            }
        }
    }
}

#[async_trait::async_trait]
impl ScanCancellationSource for SqsScanCancellationSource {
    /// Borra la cancelación anterior (ya aplicada por el pipeline) y hace long
    /// poll de la siguiente. Los malformados van a la DLQ y se devuelven como
    /// `Err(MalformedPayload | InvalidSchema)`. Nunca devuelve `Ok(None)` ni
    /// `Err(Transport)`.
    async fn next_cancellation(&self) -> Result<Option<ScanCancellation>, ConsumeError> {
        self.delete_delivered().await;
        let (message, receipt_handle) = self.queue.next_message().await;
        let body = message.body().unwrap_or_default();
        match parse_scan_cancellation(body.as_bytes()) {
            Ok(cancellation) => {
                log_cancellation_received(&cancellation);
                *lock(&self.delivered) = Some(receipt_handle);
                Ok(Some(cancellation))
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    payload_len = body.len(),
                    "cancelación malformada en la cola SQS enviada a la DLQ"
                );
                self.queue.dead_letter(&message, &receipt_handle).await;
                Err(err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_from_one_second_and_caps_at_thirty() {
        let mut d = BACKOFF_INITIAL;
        let mut seen = vec![d.as_secs()];
        for _ in 0..6 {
            d = next_backoff(d, BACKOFF_MAX);
            seen.push(d.as_secs());
        }
        assert_eq!(seen, vec![1, 2, 4, 8, 16, 30, 30]);
    }

    #[tokio::test]
    async fn acknowledger_debug_never_prints_the_receipt_handle() {
        let client = Client::from_conf(
            aws_sdk_sqs::Config::builder()
                .behavior_version(aws_config::BehaviorVersion::latest())
                .region(aws_config::Region::new("us-east-1"))
                .build(),
        );
        let ack = SqsAcknowledger {
            client,
            queue_url: "http://q".to_owned(),
            receipt_handle: "SECRET-HANDLE".to_owned(),
        };

        let printed = format!("{ack:?}");

        assert!(!printed.contains("SECRET-HANDLE"), "{printed}");
        assert!(printed.contains("http://q"));
    }
}
