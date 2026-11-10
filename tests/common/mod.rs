//! Arnés compartido de los tests de integración que corren contra un
//! LocalStack real (`localstack/localstack:4.4`, SNS + SQS + Kinesis) levantado con
//! `testcontainers`: sin mocks y sin cuenta AWS. Cada test levanta su propio
//! contenedor, así que los nombres de colas y topics nunca colisionan.
//!
//! Requiere Docker; los tests que lo usan están marcados
//! `#[ignore = "requiere Docker"]`.

// Cada binario de test (`tests/*.rs`) compila este módulo por separado y solo
// usa una parte de sus helpers.
#![allow(dead_code)]

use std::time::Duration;

use aws_sdk_kinesis::types::{Record, ShardIteratorType, StreamStatus};
use aws_sdk_sns::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_sqs::types::{Message, MessageAttributeValue, QueueAttributeName};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

pub const LOCALSTACK_TAG: &str = "4.4";
pub const REGION: &str = "us-east-1";
/// Visibilidad corta (s) de las colas de test para que la reentrega sea rápida;
/// en AWS el valor lo fija Terraform.
pub const VISIBILITY_SECONDS: &str = "2";

/// LocalStack en marcha más clientes SNS/SQS/Kinesis ya apuntados a él. El contenedor
/// se destruye al soltar este valor.
pub struct LocalStack {
    _container: ContainerAsync<GenericImage>,
    pub endpoint: String,
    pub sns: aws_sdk_sns::Client,
    pub sqs: aws_sdk_sqs::Client,
    pub kinesis: aws_sdk_kinesis::Client,
}

impl LocalStack {
    pub async fn start() -> Self {
        let container = GenericImage::new("localstack/localstack", LOCALSTACK_TAG)
            .with_exposed_port(4566.tcp())
            .with_wait_for(WaitFor::message_on_stdout("Ready."))
            .with_startup_timeout(Duration::from_secs(180))
            .start()
            .await
            .expect("el contenedor LocalStack de test debe arrancar");
        let port = container
            .get_host_port_ipv4(4566.tcp())
            .await
            .expect("LocalStack debe publicar el puerto 4566");
        let endpoint = format!("http://127.0.0.1:{port}");
        let credentials = || Credentials::new("test", "test", None, None, "localstack-test");
        let sns = aws_sdk_sns::Client::from_conf(
            aws_sdk_sns::Config::builder()
                .behavior_version(BehaviorVersion::latest())
                .region(Region::new(REGION))
                .endpoint_url(&endpoint)
                .credentials_provider(credentials())
                .build(),
        );
        let sqs = aws_sdk_sqs::Client::from_conf(
            aws_sdk_sqs::Config::builder()
                .behavior_version(BehaviorVersion::latest())
                .region(Region::new(REGION))
                .endpoint_url(&endpoint)
                .credentials_provider(credentials())
                .build(),
        );
        let kinesis = aws_sdk_kinesis::Client::from_conf(
            aws_sdk_kinesis::Config::builder()
                .behavior_version(BehaviorVersion::latest())
                .region(Region::new(REGION))
                .endpoint_url(&endpoint)
                .credentials_provider(credentials())
                .build(),
        );
        Self {
            _container: container,
            endpoint,
            sns,
            sqs,
            kinesis,
        }
    }

    /// Crea el stream Kinesis `name` de 1 shard y espera a que esté `ACTIVE`
    /// (sondea con tope de intentos).
    pub async fn create_stream(&self, name: &str) {
        self.kinesis
            .create_stream()
            .stream_name(name)
            .shard_count(1)
            .send()
            .await
            .expect("crear el stream");
        for _ in 0..100 {
            let status = self
                .kinesis
                .describe_stream_summary()
                .stream_name(name)
                .send()
                .await
                .expect("describir el stream")
                .stream_description_summary
                .expect("resumen del stream")
                .stream_status;
            if status == StreamStatus::Active {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("el stream {name} no llegó a ACTIVE");
    }

    /// Lee desde el principio (`TRIM_HORIZON`) del único shard de `stream`
    /// hasta reunir `expected` registros (o agotar los intentos).
    pub async fn read_stream(&self, stream: &str, expected: usize) -> Vec<Record> {
        let shard_id = self
            .kinesis
            .list_shards()
            .stream_name(stream)
            .send()
            .await
            .expect("listar shards")
            .shards
            .expect("shards")
            .remove(0)
            .shard_id;
        let mut iterator = self
            .kinesis
            .get_shard_iterator()
            .stream_name(stream)
            .shard_id(shard_id)
            .shard_iterator_type(ShardIteratorType::TrimHorizon)
            .send()
            .await
            .expect("iterador del shard")
            .shard_iterator;
        let mut records = Vec::new();
        for _ in 0..50 {
            let Some(current) = iterator.take() else {
                break;
            };
            let out = self
                .kinesis
                .get_records()
                .shard_iterator(current)
                .send()
                .await
                .expect("leer registros");
            records.extend(out.records);
            if records.len() >= expected {
                break;
            }
            iterator = out.next_shard_iterator;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        records
    }

    pub async fn queue_arn(&self, queue_url: &str) -> String {
        self.sqs
            .get_queue_attributes()
            .queue_url(queue_url)
            .attribute_names(QueueAttributeName::QueueArn)
            .send()
            .await
            .expect("atributos de la cola")
            .attributes
            .expect("atributos")
            .remove(&QueueAttributeName::QueueArn)
            .expect("arn de la cola")
    }

    pub async fn create_queue(&self, name: &str) -> String {
        self.sqs
            .create_queue()
            .queue_name(name)
            .send()
            .await
            .expect("crear cola")
            .queue_url
            .expect("url de la cola")
    }

    /// Crea `name` (visibilidad corta, `RedrivePolicy` con `maxReceiveCount: 3`
    /// hacia `<name>-redrive-dlq`) y su DLQ explícita de malformados
    /// `<name>-dlq`; devuelve `(queue_url, malformed_dlq_url, redrive_dlq_url)`.
    pub async fn queue_with_dlqs(&self, name: &str) -> (String, String, String) {
        let malformed_dlq = self.create_queue(&format!("{name}-dlq")).await;
        let redrive_dlq = self.create_queue(&format!("{name}-redrive-dlq")).await;
        let redrive_arn = self.queue_arn(&redrive_dlq).await;
        let queue = self
            .sqs
            .create_queue()
            .queue_name(name)
            .attributes(QueueAttributeName::VisibilityTimeout, VISIBILITY_SECONDS)
            .attributes(
                QueueAttributeName::RedrivePolicy,
                format!(r#"{{"deadLetterTargetArn":"{redrive_arn}","maxReceiveCount":3}}"#),
            )
            .send()
            .await
            .expect("crear cola")
            .queue_url
            .expect("url de la cola");
        (queue, malformed_dlq, redrive_dlq)
    }

    /// Crea el topic `topic` y una cola `queue` suscrita con
    /// `RawMessageDelivery=true` (lo publicado llega tal cual, con el atributo
    /// `routing_key`) y, si se indica, una `FilterPolicy`; devuelve
    /// `(topic_arn, queue_url)`.
    pub async fn topic_with_raw_queue(
        &self,
        topic: &str,
        queue: &str,
        filter_policy: Option<&str>,
    ) -> (String, String) {
        let topic_arn = self
            .sns
            .create_topic()
            .name(topic)
            .send()
            .await
            .expect("crear topic")
            .topic_arn
            .expect("topic arn");
        let queue_url = self.create_queue(queue).await;
        let queue_arn = self.queue_arn(&queue_url).await;
        let mut subscribe = self
            .sns
            .subscribe()
            .topic_arn(&topic_arn)
            .protocol("sqs")
            .endpoint(&queue_arn)
            .attributes("RawMessageDelivery", "true");
        if let Some(policy) = filter_policy {
            subscribe = subscribe.attributes("FilterPolicy", policy);
        }
        subscribe.send().await.expect("suscribir la cola al topic");
        (topic_arn, queue_url)
    }

    pub async fn send(&self, queue_url: &str, body: &str, attributes: &[(&str, &str)]) {
        let mut request = self
            .sqs
            .send_message()
            .queue_url(queue_url)
            .message_body(body);
        for (name, value) in attributes {
            request = request.message_attributes(
                *name,
                MessageAttributeValue::builder()
                    .data_type("String")
                    .string_value(*value)
                    .build()
                    .expect("data_type presente"),
            );
        }
        request.send().await.expect("enviar mensaje");
    }

    /// Recibe (y borra) un mensaje de `queue_url` esperando hasta `wait`
    /// segundos en total; `None` si no llega ninguno.
    pub async fn receive_and_delete(&self, queue_url: &str, wait: u64) -> Option<Message> {
        let deadline = std::time::Instant::now() + Duration::from_secs(wait);
        while std::time::Instant::now() < deadline {
            let out = self
                .sqs
                .receive_message()
                .queue_url(queue_url)
                .message_attribute_names("All")
                .wait_time_seconds(1)
                .max_number_of_messages(1)
                .send()
                .await
                .expect("recibir de la cola");
            if let Some(message) = out.messages.and_then(|m| m.into_iter().next()) {
                if let Some(handle) = message.receipt_handle() {
                    let _ = self
                        .sqs
                        .delete_message()
                        .queue_url(queue_url)
                        .receipt_handle(handle)
                        .send()
                        .await;
                }
                return Some(message);
            }
        }
        None
    }

    /// `true` si la cola no tiene mensajes visibles, en vuelo ni demorados.
    pub async fn is_empty(&self, queue_url: &str) -> bool {
        let attributes = self
            .sqs
            .get_queue_attributes()
            .queue_url(queue_url)
            .attribute_names(QueueAttributeName::All)
            .send()
            .await
            .expect("atributos de la cola")
            .attributes
            .expect("atributos");
        [
            QueueAttributeName::ApproximateNumberOfMessages,
            QueueAttributeName::ApproximateNumberOfMessagesNotVisible,
            QueueAttributeName::ApproximateNumberOfMessagesDelayed,
        ]
        .iter()
        .all(|name| attributes.get(name).map(String::as_str) == Some("0"))
    }
}
