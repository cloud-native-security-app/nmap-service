//! Conexión SSH al objetivo y ejecución de comandos remotos, con verificación
//! de identidad del host por Trust On First Use ([`HostKeyStore`]).
//!
//! [`connect`] establece la sesión (autenticación por contraseña) y, durante el
//! handshake, compara el fingerprint SHA-256 de la clave pública del host contra
//! el almacenado en un [`HostKeyStore`]:
//!
//! - si el host es desconocido, se registra su fingerprint y se continúa;
//! - si coincide con el registrado, se continúa;
//! - si difiere, la conexión se **rechaza** con [`SshError::HostKeyMismatch`]
//!   (posible ataque man-in-the-middle). Nunca se acepta una clave sin
//!   verificarla (ver `docs/security-scope.md`).
//!
//! Las credenciales solo se exponen en el punto exacto en que se entregan a
//! `russh` para autenticar; nunca se escriben en logs ni en mensajes de error.
//!
//! ## Desviación respecto al `acceptance` de la feature
//!
//! El `acceptance` describe `connect(host, user, credentials)`. La firma real
//! añade, por decisión de diseño ya confirmada:
//!
//! - `port`: el objetivo no siempre escucha en el 22 (los contenedores de
//!   prueba usan 2222 y un puerto de host aleatorio).
//! - `store`: el almacén de host keys es obligatorio; sin él no hay TOFU.
//! - `timeouts`: los `Duration` de conexión y de comando se pasan de forma
//!   explícita (provienen de `config`, ver feature 2); no se hardcodean.
//!
//! Solo se implementa autenticación por contraseña. La autenticación por clave
//! pública queda como posible extensión futura (`russh` la soporta vía
//! `authenticate_publickey`), fuera del alcance de esta feature.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client::{self, AuthResult, Handle};
use russh::keys::ssh_key::PublicKey;
use russh::keys::{HashAlg, PublicKeyOrCertificate};
use russh::ChannelMsg;
use serde::{Deserialize, Serialize};

use crate::domain::SshCredentialsRef;

/// Fingerprint SHA-256 de la clave pública de un host SSH.
///
/// Newtype sobre el digest crudo de 32 bytes. Su representación textual sigue el
/// formato de OpenSSH (`SHA256:<base64-sin-padding>`), disponible vía
/// [`Fingerprint::openssh_format`] / `Display`.
///
/// Deriva `Serialize`/`Deserialize` para que el almacén respaldado por MongoDB
/// (feature `mongo_persistence`) pueda persistirlo.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Fingerprint {
    sha256: [u8; 32],
}

impl Fingerprint {
    /// Calcula el fingerprint SHA-256 de la clave pública de un host tal como la
    /// entrega `russh` durante el handshake.
    pub fn from_host_public_key(key: &PublicKey) -> Self {
        let digest = key.fingerprint(HashAlg::Sha256);
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(digest.as_bytes());
        Self { sha256 }
    }

    /// Construye un fingerprint a partir de su digest SHA-256 crudo.
    ///
    /// Pensado para tests y para reconstruirlo desde el almacén persistente.
    pub fn from_sha256_bytes(sha256: [u8; 32]) -> Self {
        Self { sha256 }
    }

    /// Digest SHA-256 crudo (32 bytes).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.sha256
    }

    /// Representación textual en el formato de OpenSSH
    /// (`SHA256:<base64-sin-padding>`).
    pub fn openssh_format(&self) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::from("SHA256:");
        for chunk in self.sha256.chunks(3) {
            let b0 = chunk[0] as usize;
            out.push(ALPHABET[b0 >> 2] as char);
            match chunk.len() {
                1 => out.push(ALPHABET[(b0 & 0b11) << 4] as char),
                2 => {
                    let b1 = chunk[1] as usize;
                    out.push(ALPHABET[((b0 & 0b11) << 4) | (b1 >> 4)] as char);
                    out.push(ALPHABET[(b1 & 0b1111) << 2] as char);
                }
                _ => {
                    let b1 = chunk[1] as usize;
                    let b2 = chunk[2] as usize;
                    out.push(ALPHABET[((b0 & 0b11) << 4) | (b1 >> 4)] as char);
                    out.push(ALPHABET[((b1 & 0b1111) << 2) | (b2 >> 6)] as char);
                    out.push(ALPHABET[b2 & 0b111111] as char);
                }
            }
        }
        out
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.openssh_format())
    }
}

/// Error al consultar o actualizar un [`HostKeyStore`].
///
/// Las implementaciones respaldadas por IO (p. ej. la de MongoDB en
/// `repository`) pueden fallar; la implementación en memoria nunca devuelve
/// `Err`. Ningún mensaje incluye credenciales ni material de clave.
#[derive(Debug, thiserror::Error)]
pub enum HostKeyStoreError {
    /// El almacén de respaldo no está disponible (p. ej. MongoDB caído o
    /// inalcanzable). La conexión SSH se aborta en vez de continuar sin poder
    /// verificar la identidad del host.
    #[error("almacén de host keys no disponible: {0}")]
    Unavailable(String),

    /// Un registro del almacén tiene un formato inesperado o está corrupto
    /// (p. ej. un fingerprint que no son 64 caracteres hexadecimales).
    #[error("registro de host key inválido: {0}")]
    Corrupt(String),
}

/// Almacén de fingerprints de host conocidos para la verificación TOFU.
///
/// La primera conexión a un host guarda su fingerprint vía [`remember`];
/// conexiones posteriores lo consultan vía [`known_fingerprint`] y rechazan la
/// conexión si el fingerprint actual no coincide.
///
/// El trait es `async` (vía `async-trait`) y dyn-compatible: se comparte
/// como `Arc<dyn HostKeyStore>`. Ambos métodos toman `&self` y usan mutabilidad
/// interior, de modo que no hace falta un `Mutex` externo. La implementación
/// persistente (MongoDB) vive en `repository` para que el trust store sobreviva
/// reinicios y se comparta entre réplicas del servicio.
///
/// [`remember`]: HostKeyStore::remember
/// [`known_fingerprint`]: HostKeyStore::known_fingerprint
#[async_trait::async_trait]
pub trait HostKeyStore: Send + Sync {
    /// Devuelve el fingerprint registrado para `host`, o `None` si el host es
    /// desconocido.
    ///
    /// # Errores
    ///
    /// [`HostKeyStoreError`] si el almacén de respaldo no está disponible o el
    /// registro almacenado está corrupto.
    async fn known_fingerprint(&self, host: &str)
        -> Result<Option<Fingerprint>, HostKeyStoreError>;

    /// Registra (o sobrescribe) el fingerprint asociado a `host`.
    ///
    /// # Errores
    ///
    /// [`HostKeyStoreError`] si el almacén de respaldo no está disponible.
    async fn remember(&self, host: &str, fingerprint: Fingerprint)
        -> Result<(), HostKeyStoreError>;
}

/// Implementación de [`HostKeyStore`] en memoria, para tests y desarrollo.
///
/// No sobrevive a un reinicio del proceso; la implementación persistente vive en
/// `repository` (feature `mongo_persistence`). La sincronización es un
/// [`std::sync::Mutex`] interno tomado y soltado dentro de cada método (sin
/// cruzar ningún `.await`), por lo que sus operaciones son de hecho síncronas y
/// nunca devuelven `Err`.
#[derive(Debug, Default)]
pub struct InMemoryHostKeyStore {
    entries: Mutex<HashMap<String, Fingerprint>>,
}

impl InMemoryHostKeyStore {
    /// Crea un almacén vacío.
    pub fn new() -> Self {
        Self::default()
    }

    fn entries(&self) -> std::sync::MutexGuard<'_, HashMap<String, Fingerprint>> {
        match self.entries.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

#[async_trait::async_trait]
impl HostKeyStore for InMemoryHostKeyStore {
    async fn known_fingerprint(
        &self,
        host: &str,
    ) -> Result<Option<Fingerprint>, HostKeyStoreError> {
        Ok(self.entries().get(host).cloned())
    }

    async fn remember(
        &self,
        host: &str,
        fingerprint: Fingerprint,
    ) -> Result<(), HostKeyStoreError> {
        self.entries().insert(host.to_owned(), fingerprint);
        Ok(())
    }
}

/// Salida de un comando ejecutado en el host remoto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// Contenido de `stdout` (decodificado como UTF-8, con reemplazo de bytes
    /// inválidos).
    pub stdout: String,
    /// Contenido de `stderr` (decodificado como UTF-8, con reemplazo de bytes
    /// inválidos).
    pub stderr: String,
    /// Código de salida del comando. Es `-1` si el servidor cerró el canal sin
    /// enviar un `exit-status` (p. ej. terminación por señal).
    pub exit_code: i32,
}

/// Tiempos máximos aplicados a las operaciones SSH.
///
/// Sus valores provienen de `config` (variables de entorno, feature 2); este
/// módulo no define ningún valor por defecto.
#[derive(Debug, Clone, Copy)]
pub struct SshTimeouts {
    /// Tiempo máximo para establecer la conexión y autenticar.
    pub connect: Duration,
    /// Tiempo máximo para la ejecución de un comando remoto.
    pub command: Duration,
}

/// Error de una operación SSH.
///
/// Cada modo de fallo relevante para el pipeline es una variante distinta; no
/// hay un error genérico. Ningún mensaje incluye credenciales ni contenido de
/// claves (ver `docs/security-scope.md`).
#[derive(Debug, thiserror::Error)]
pub enum SshError {
    /// El servidor rechazó la autenticación (usuario o contraseña incorrectos,
    /// o método no permitido).
    #[error("autenticación SSH rechazada")]
    AuthFailed,

    /// Se agotó el tiempo de espera de la conexión o del comando.
    #[error("tiempo de espera agotado en la operación SSH")]
    Timeout,

    /// No se pudo alcanzar el host por la red. Contiene el destino y el motivo
    /// de red, nunca credenciales.
    #[error("host inalcanzable: {0}")]
    Unreachable(String),

    /// El fingerprint de la clave del host no coincide con el registrado
    /// previamente (posible man-in-the-middle). La conexión se rechaza.
    #[error(
        "la identidad del host {host} no coincide con la registrada (posible MITM); conexión rechazada"
    )]
    HostKeyMismatch {
        /// Host cuyo fingerprint no coincidió.
        host: String,
    },

    /// No se pudo consultar o actualizar el almacén de host keys (TOFU). La
    /// conexión se aborta: sin acceso al trust store no se puede verificar la
    /// identidad del host.
    #[error("no se pudo verificar la identidad del host: {0}")]
    HostKeyStore(#[from] HostKeyStoreError),

    /// Fallo del protocolo SSH no cubierto por las demás variantes.
    #[error("error de protocolo SSH: {0}")]
    Protocol(String),

    /// Fallo de E/S sobre la conexión ya establecida.
    #[error("error de E/S en la conexión SSH: {0}")]
    Io(String),
}

impl SshError {
    fn from_russh(err: russh::Error, endpoint: Option<(&str, u16)>) -> Self {
        match err {
            russh::Error::ConnectionTimeout
            | russh::Error::InactivityTimeout
            | russh::Error::KeepaliveTimeout
            | russh::Error::Elapsed(_) => SshError::Timeout,
            russh::Error::NotAuthenticated
            | russh::Error::NoAuthMethod
            | russh::Error::UnsupportedAuthMethod => SshError::AuthFailed,
            russh::Error::IO(io) => classify_io(&io, endpoint),
            russh::Error::HUP | russh::Error::Disconnect => SshError::Unreachable(format!(
                "{}: conexión cerrada por el host",
                target(endpoint)
            )),
            other => SshError::Protocol(other.to_string()),
        }
    }
}

impl From<russh::Error> for SshError {
    fn from(err: russh::Error) -> Self {
        Self::from_russh(err, None)
    }
}

fn target(endpoint: Option<(&str, u16)>) -> String {
    match endpoint {
        Some((host, port)) => format!("{host}:{port}"),
        None => "objetivo".to_owned(),
    }
}

fn classify_io(io: &std::io::Error, endpoint: Option<(&str, u16)>) -> SshError {
    use std::io::ErrorKind;
    match io.kind() {
        ErrorKind::ConnectionRefused
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted
        | ErrorKind::NotConnected
        | ErrorKind::HostUnreachable
        | ErrorKind::NetworkUnreachable
        | ErrorKind::AddrNotAvailable
        | ErrorKind::TimedOut => {
            SshError::Unreachable(format!("{}: {}", target(endpoint), io.kind()))
        }
        _ => SshError::Io(io.to_string()),
    }
}

/// Verificador de host key para el handshake de `russh`.
///
/// No guarda credenciales. Comparte dos slots con [`connect`], que los lee tras
/// el handshake para traducir el fallo a la variante de [`SshError`] correcta:
///
/// - `mismatch` ([`AtomicBool`]): `check_server_key` detectó un fingerprint
///   distinto al registrado -> [`SshError::HostKeyMismatch`].
/// - `store_error` ([`Mutex`]): `check_server_key` no pudo consultar/actualizar
///   el [`HostKeyStore`] -> [`SshError::HostKeyStore`].
///
/// En ambos casos `check_server_key` devuelve `Ok(false)` (rechazo): nunca se
/// acepta una clave sin verificarla.
struct Verifier {
    host: String,
    store: Arc<dyn HostKeyStore>,
    mismatch: Arc<AtomicBool>,
    store_error: Arc<Mutex<Option<HostKeyStoreError>>>,
}

impl client::Handler for Verifier {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let key = match server_public_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key,
            PublicKeyOrCertificate::Certificate(_) => return Ok(false),
        };
        let current = Fingerprint::from_host_public_key(key);

        match verify_fingerprint(self.store.as_ref(), &self.host, &current).await {
            Ok(true) => Ok(true),
            Ok(false) => {
                self.mismatch.store(true, Ordering::SeqCst);
                Ok(false)
            }
            Err(err) => {
                if let Ok(mut slot) = self.store_error.lock() {
                    *slot = Some(err);
                }
                Ok(false)
            }
        }
    }
}

/// Decisión TOFU sobre el fingerprint `current` del host `host`:
///
/// - host desconocido en `store` -> se registra y se acepta (`Ok(true)`);
/// - fingerprint registrado igual al actual -> se acepta (`Ok(true)`);
/// - fingerprint registrado distinto -> se rechaza (`Ok(false)`) y **no** se
///   sobrescribe el registrado;
/// - fallo del almacén -> `Err(HostKeyStoreError)` (la conexión se abortará).
async fn verify_fingerprint(
    store: &dyn HostKeyStore,
    host: &str,
    current: &Fingerprint,
) -> Result<bool, HostKeyStoreError> {
    match store.known_fingerprint(host).await? {
        None => {
            store.remember(host, current.clone()).await?;
            Ok(true)
        }
        Some(known) => Ok(&known == current),
    }
}

/// Sesión SSH establecida y autenticada contra el host objetivo.
pub struct SshSession {
    handle: Handle<Verifier>,
    command_timeout: Duration,
}

impl fmt::Debug for SshSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshSession")
            .field("command_timeout", &self.command_timeout)
            .finish_non_exhaustive()
    }
}

impl SshSession {
    /// Ejecuta `cmd` en el host remoto y devuelve su `stdout`, `stderr` y código
    /// de salida.
    ///
    /// # Errores
    ///
    /// - [`SshError::Timeout`] si el comando no termina dentro del timeout de
    ///   comando configurado.
    /// - [`SshError::Io`] / [`SshError::Protocol`] si falla la apertura del
    ///   canal o el transporte.
    pub async fn run_command(&self, cmd: &str) -> Result<CommandOutput, SshError> {
        let exec = async {
            let mut channel = self.handle.channel_open_session().await?;
            channel.exec(true, cmd).await?;

            let mut stdout: Vec<u8> = Vec::new();
            let mut stderr: Vec<u8> = Vec::new();
            let mut exit_code: Option<u32> = None;

            while let Some(msg) = channel.wait().await {
                match msg {
                    ChannelMsg::Data { ref data } => stdout.extend_from_slice(data),
                    ChannelMsg::ExtendedData { ref data, ext: 1 } => stderr.extend_from_slice(data),
                    ChannelMsg::ExitStatus { exit_status } => exit_code = Some(exit_status),
                    _ => {}
                }
            }

            Ok::<CommandOutput, russh::Error>(CommandOutput {
                stdout: String::from_utf8_lossy(&stdout).into_owned(),
                stderr: String::from_utf8_lossy(&stderr).into_owned(),
                exit_code: exit_code.map_or(-1, |code| code as i32),
            })
        };

        match tokio::time::timeout(self.command_timeout, exec).await {
            Err(_) => Err(SshError::Timeout),
            Ok(Ok(output)) => Ok(output),
            Ok(Err(err)) => Err(SshError::from(err)),
        }
    }
}

/// Puerto (hexagonal) para establecer una sesión SSH con el objetivo.
///
/// Abstrae la función libre [`connect`] tras un trait dyn-compatible
/// (`Arc<dyn RemoteExecutor>`) para poder inyectar el adaptador real
/// ([`RusshExecutor`]) en el pipeline y sustituirlo por un doble en tests sin
/// levantar un `sshd`. La verificación TOFU y el manejo de credenciales siguen
/// viviendo en el adaptador concreto (ver `docs/security-scope.md`).
#[async_trait::async_trait]
pub trait RemoteExecutor: Send + Sync {
    /// Se conecta por SSH a `host:port`, verifica la identidad del host (TOFU
    /// contra `store`) y autentica a `user` con `credentials`.
    ///
    /// # Errores
    ///
    /// Las mismas variantes de [`SshError`] que documenta [`connect`]
    /// (timeout, host inalcanzable, host key mismatch, fallo del trust store,
    /// autenticación rechazada, protocolo/E/S).
    async fn connect(
        &self,
        host: &str,
        port: u16,
        user: &str,
        credentials: &SshCredentialsRef,
        store: &Arc<dyn HostKeyStore>,
        timeouts: SshTimeouts,
    ) -> Result<Box<dyn RemoteSession>, SshError>;
}

/// Puerto (hexagonal) para ejecutar comandos sobre una sesión SSH ya
/// establecida.
///
/// Es lo que [`RemoteExecutor::connect`] devuelve y lo que `scanner` consume
/// para lanzar `nmap`. El adaptador real es [`SshSession`].
#[async_trait::async_trait]
pub trait RemoteSession: Send + Sync {
    /// Ejecuta `cmd` en el host remoto y devuelve su `stdout`, `stderr` y código
    /// de salida.
    ///
    /// # Errores
    ///
    /// - [`SshError::Timeout`] si el comando excede el timeout configurado.
    /// - [`SshError::Io`] / [`SshError::Protocol`] ante fallos de canal o
    ///   transporte.
    async fn run_command(&self, cmd: &str) -> Result<CommandOutput, SshError>;
}

#[async_trait::async_trait]
impl RemoteSession for SshSession {
    async fn run_command(&self, cmd: &str) -> Result<CommandOutput, SshError> {
        SshSession::run_command(self, cmd).await
    }
}

/// Adaptador de producción de [`RemoteExecutor`]: delega en la función libre
/// [`connect`] (cliente `russh`) y entrega la [`SshSession`] resultante como
/// `Box<dyn RemoteSession>`.
#[derive(Debug, Clone, Copy, Default)]
pub struct RusshExecutor;

#[async_trait::async_trait]
impl RemoteExecutor for RusshExecutor {
    async fn connect(
        &self,
        host: &str,
        port: u16,
        user: &str,
        credentials: &SshCredentialsRef,
        store: &Arc<dyn HostKeyStore>,
        timeouts: SshTimeouts,
    ) -> Result<Box<dyn RemoteSession>, SshError> {
        let session = connect(host, port, user, credentials, store, timeouts).await?;
        Ok(Box::new(session))
    }
}

/// Se conecta por SSH a `host:port`, verifica la identidad del host (TOFU contra
/// `store`) y autentica a `user` con `credentials` (contraseña).
///
/// La credencial solo se expone en el instante en que se entrega a `russh` para
/// autenticar.
///
/// # Errores
///
/// - [`SshError::Timeout`] si no se logra conectar/autenticar dentro de
///   `timeouts.connect`.
/// - [`SshError::Unreachable`] si el host no es alcanzable por la red.
/// - [`SshError::HostKeyMismatch`] si el fingerprint del host difiere del
///   registrado en `store` (la conexión se rechaza).
/// - [`SshError::HostKeyStore`] si no se puede consultar/actualizar `store`
///   (p. ej. el almacén respaldado por MongoDB está caído).
/// - [`SshError::AuthFailed`] si el servidor rechaza las credenciales.
/// - [`SshError::Protocol`] / [`SshError::Io`] para el resto de fallos.
pub async fn connect(
    host: &str,
    port: u16,
    user: &str,
    credentials: &SshCredentialsRef,
    store: &Arc<dyn HostKeyStore>,
    timeouts: SshTimeouts,
) -> Result<SshSession, SshError> {
    let config = Arc::new(client::Config::default());
    let mismatch = Arc::new(AtomicBool::new(false));
    let store_error: Arc<Mutex<Option<HostKeyStoreError>>> = Arc::new(Mutex::new(None));
    let verifier = Verifier {
        host: host.to_owned(),
        store: Arc::clone(store),
        mismatch: Arc::clone(&mismatch),
        store_error: Arc::clone(&store_error),
    };

    let handshake = client::connect(config, (host, port), verifier);
    let mut handle = match tokio::time::timeout(timeouts.connect, handshake).await {
        Err(_) => return Err(SshError::Timeout),
        Ok(Ok(handle)) => handle,
        Ok(Err(err)) => {
            if let Some(store_err) = store_error.lock().ok().and_then(|mut slot| slot.take()) {
                return Err(SshError::HostKeyStore(store_err));
            }
            if mismatch.load(Ordering::SeqCst) {
                return Err(SshError::HostKeyMismatch {
                    host: host.to_owned(),
                });
            }
            return Err(SshError::from_russh(err, Some((host, port))));
        }
    };

    let auth = handle
        .authenticate_password(user, credentials.expose())
        .await
        .map_err(|err| SshError::from_russh(err, Some((host, port))))?;

    match auth {
        AuthResult::Success => Ok(SshSession {
            handle,
            command_timeout: timeouts.command,
        }),
        AuthResult::Failure { .. } => Err(SshError::AuthFailed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_handle(store: InMemoryHostKeyStore) -> Arc<dyn HostKeyStore> {
        Arc::new(store)
    }

    #[tokio::test]
    async fn in_memory_store_remembers_and_returns_fingerprint() {
        let store = InMemoryHostKeyStore::new();
        let fp = Fingerprint::from_sha256_bytes([7u8; 32]);

        assert_eq!(store.known_fingerprint("192.0.2.10").await.unwrap(), None);

        store.remember("192.0.2.10", fp.clone()).await.unwrap();

        assert_eq!(
            store.known_fingerprint("192.0.2.10").await.unwrap(),
            Some(fp)
        );
        assert_eq!(store.known_fingerprint("192.0.2.11").await.unwrap(), None);
    }

    #[test]
    fn fingerprint_json_round_trip_preserves_digest() {
        let original = Fingerprint::from_sha256_bytes([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ]);

        let json = serde_json::to_string(&original).expect("serializa");
        let restored: Fingerprint = serde_json::from_str(&json).expect("deserializa");

        assert_eq!(restored, original);
    }

    #[test]
    fn fingerprint_openssh_format_has_expected_shape() {
        let zero = Fingerprint::from_sha256_bytes([0u8; 32]);
        let rendered = zero.openssh_format();

        assert_eq!(rendered, format!("SHA256:{}", "A".repeat(43)));

        let other = Fingerprint::from_sha256_bytes([0xffu8; 32]);
        assert!(other.openssh_format().starts_with("SHA256:"));
        assert_ne!(other.openssh_format(), rendered);
    }

    #[test]
    fn ssh_error_display_never_mentions_credentials() {
        let rendered = [
            SshError::AuthFailed.to_string(),
            SshError::Timeout.to_string(),
            SshError::Unreachable("192.0.2.10:22: connection refused".to_owned()).to_string(),
            SshError::HostKeyMismatch {
                host: "192.0.2.10".to_owned(),
            }
            .to_string(),
            SshError::Protocol("kex failed".to_owned()).to_string(),
            SshError::Io("broken pipe".to_owned()).to_string(),
            SshError::HostKeyStore(HostKeyStoreError::Unavailable("mongo caído".to_owned()))
                .to_string(),
            SshError::HostKeyStore(HostKeyStoreError::Corrupt("hex de 10 chars".to_owned()))
                .to_string(),
        ]
        .join(" | ");

        for banned in [
            "password",
            "secret",
            "contraseña",
            "credential",
            "credencial",
        ] {
            assert!(
                !rendered.to_lowercase().contains(banned),
                "el mensaje de error no debe mencionar {banned}: {rendered}"
            );
        }
    }

    #[tokio::test]
    async fn tofu_decision_unknown_host_is_remembered_and_accepted() {
        let store = store_handle(InMemoryHostKeyStore::new());
        let fp = Fingerprint::from_sha256_bytes([1u8; 32]);

        let accepted = verify_fingerprint(store.as_ref(), "target", &fp)
            .await
            .expect("el almacén en memoria no falla");

        assert!(accepted);
        assert_eq!(store.known_fingerprint("target").await.unwrap(), Some(fp));
    }

    #[tokio::test]
    async fn tofu_decision_matching_fingerprint_is_accepted() {
        let seed = InMemoryHostKeyStore::new();
        let fp = Fingerprint::from_sha256_bytes([2u8; 32]);
        seed.remember("target", fp.clone()).await.unwrap();
        let store = store_handle(seed);

        assert!(verify_fingerprint(store.as_ref(), "target", &fp)
            .await
            .expect("el almacén en memoria no falla"));
    }

    #[tokio::test]
    async fn tofu_decision_changed_fingerprint_is_rejected() {
        let seed = InMemoryHostKeyStore::new();
        seed.remember("target", Fingerprint::from_sha256_bytes([3u8; 32]))
            .await
            .unwrap();
        let store = store_handle(seed);

        let current = Fingerprint::from_sha256_bytes([9u8; 32]);
        assert!(!verify_fingerprint(store.as_ref(), "target", &current)
            .await
            .expect("el almacén en memoria no falla"));
        // el fingerprint registrado no se sobrescribe ante un mismatch
        assert_eq!(
            store.known_fingerprint("target").await.unwrap(),
            Some(Fingerprint::from_sha256_bytes([3u8; 32]))
        );
    }
}
