# Exploración: crate SSH para feature 4 `ssh_client` (TOFU)

> Investigación del subagente Explore (2026-08-27), guardada por el leader
> (el Explore opera en solo-lectura). Verificar firmas exactas contra
> docs.rs de la versión que se fije al implementar.

## Contexto del repo

- `src/ssh.rs`: hoy solo stub. Menciona TOFU + `HostKeyStore`.
- `Cargo.toml`: sin dependencia SSH todavía. Ya presentes: `tokio 1`
  (`rt-multi-thread`, `macros`), `secrecy 0.10`, `thiserror 2`, `tracing 0.1`,
  `time 0.3`. Dev-dep: `testcontainers 0.24`.
- `docs/architecture.md`: admite lib síncrona con `spawn_blocking` pero
  penaliza; el almacén persistente de host keys va en `repository` (Mongo),
  `ssh` solo define el trait `HostKeyStore` + impl en memoria.
- `docs/security-scope.md`: TOFU obligatorio; **prohibido** deshabilitar la
  verificación de host key; credenciales nunca en logs ni en errores.
- `feature_list.json` feature 7: implementará `HostKeyStore` sobre Mongo →
  feature 4 debe dejar el trait bien definido.

**Requisito que decide la elección:** acceso programático al host key del
servidor durante el handshake, con almacén de confianza propio (no un
`known_hosts` de archivo).

## Recomendación final: `russh` directo

`russh = "0.63"` en `Cargo.toml` (sin features extra). Opcional `ssh-key =
"0.6"` como dep directa si el tipo `Fingerprint` del trait `HostKeyStore`
público debe venir de ahí en vez de `russh::keys::ssh_key`.

Razones:
1. **Único** con hook de primera clase para inspeccionar el host key en el
   handshake: `russh::client::Handler::check_server_key`. La impl por
   defecto **rechaza todas las claves** → encaja con security-scope.
2. Async-nativo sobre tokio, sin binarios externos ni FFI C.
3. `russh::Error` tiene variantes finas (`KeyChanged`, `ConnectionTimeout`/
   `Elapsed`, `IO(ErrorKind)`, `NotAuthenticated`) para mapear a las 4
   variantes de `SshError` sin parsear texto.
4. Activo, release 0.63.1 (2026-08-23), Apache-2.0. Sucesor de `thrussh`.

Coste asumido: escribir el `client::Handler`, el bucle `channel.wait()` para
stdout/stderr/exit y los `tokio::time::timeout` explícitos (russh no impone
timeout de conexión por sí solo).

## Alternativas descartadas

- **`async-ssh2-tokio`** (wrapper de alto nivel sobre russh): `execute()`
  cómodo (`stdout`/`stderr`/`exit_status`), pero `ServerCheckMethod`
  (`#[non_exhaustive]`) solo ofrece `NoCheck` / `PublicKey` / `known_hosts`;
  no expone la clave del servidor ni acepta closure/trait → no permite TOFU
  con almacén propio sin bajar a russh igualmente. Útil como referencia del
  bucle de `execute`.
- **`thrussh`**: deprecado, sin mantenimiento. No usar.
- **`ssh2`** (libssh2 FFI): síncrono → `spawn_blocking` en cada operación;
  arrastra libssh2 C. Expone `Session::host_key()` pero el coste async no
  compensa.
- **`openssh`** (wrapper del binario `ssh`): requiere cliente OpenSSH
  instalado; host key check lo hace el binario contra `known_hosts`, sin
  hook para `HostKeyStore` propio; errores opacos (parseo de stderr).
- **`makiko`** / **`async-ssh2-russh`**: técnicamente viables, menos
  adoptados/mantenidos que russh, sin ventaja aquí.

## Mapeo a `SshError`

| Caso feature 4 | Origen en `russh` | Variante `SshError` |
|---|---|---|
| Auth fallida | `AuthResult::Failure` de `authenticate_*` (NO es `Err`); o `Error::NotAuthenticated` | `AuthFailed` |
| Timeout | `tokio::time::timeout` → `Elapsed`; `Error::ConnectionTimeout` / `Elapsed` | `Timeout` |
| Host inalcanzable | `Error::IO(e)` con `e.kind()` ∈ {`ConnectionRefused`, `HostUnreachable`, `NetworkUnreachable`, `TimedOut`}; `Error::Disconnect`/`HUP` al conectar | `Unreachable(String)` |
| Host key mismatch | `check_server_key` → `Ok(false)` / tu `Err`; o `Error::KeyChanged` / `Error::UnknownKey` | `HostKeyMismatch` |

## Fragmentos de API de referencia (russh 0.63.x — verificar firmas)

`check_server_key` (0.63.x):
```rust
fn check_server_key(
    &mut self,
    server_public_key: &russh::keys::PublicKeyOrCertificate,
) -> impl Future<Output = Result<bool, Self::Error>> + Send;
```
En 0.4x–0.5x el parámetro era `&russh::keys::key::PublicKey` / `&ssh_key::PublicKey`.

Handler + TOFU:
```rust
struct Verifier<S: HostKeyStore> {
    host: String,
    store: Arc<Mutex<S>>,
    mismatch: bool, // se lee tras connect() para traducir el error
}

impl<S: HostKeyStore + Send> russh::client::Handler for Verifier<S> {
    type Error = russh::Error; // o SshError si implementas From<russh::Error>

    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let pk = match key {
            russh::keys::PublicKeyOrCertificate::PublicKey(k) => k,
            _ => return Ok(false), // sin certificados en este servicio
        };
        let fp = pk.fingerprint(russh::keys::ssh_key::HashAlg::Sha256);
        let mut store = self.store.lock().await;
        match store.known_fingerprint(&self.host) {
            None => { store.remember(&self.host, fp.into()); Ok(true) }
            Some(known) if known == fp.into() => Ok(true),
            Some(_) => { self.mismatch = true; Ok(false) }
        }
    }
}
```

Connect + auth (con timeout):
```rust
let config = Arc::new(russh::client::Config::default());
let mut session = tokio::time::timeout(
    connect_timeout,
    russh::client::connect(config, (host.as_str(), port), verifier),
).await.map_err(|_| SshError::Timeout)??; // 1er ? = Elapsed, 2o = russh::Error

let ok = session
    .authenticate_password(user, password.expose_secret())
    .await?
    .success();
if !ok { return Err(SshError::AuthFailed); }
```
Auth por clave: `russh::keys::load_secret_key(path, passphrase)` /
`decode_secret_key(&pem, pass)`, luego
`session.authenticate_publickey(user, russh::keys::PrivateKeyWithHashAlg::new(Arc::new(kp), None))`.

Ejecución de comando (stdout/stderr/exit):
```rust
let mut channel = session.channel_open_session().await?;
channel.exec(true, cmd).await?; // want_reply = true
let (mut out, mut err, mut code) = (Vec::new(), Vec::new(), None);
while let Some(msg) = channel.wait().await {
    match msg {
        russh::ChannelMsg::Data { ref data } => out.extend_from_slice(data),
        russh::ChannelMsg::ExtendedData { ref data, ext } if ext == 1 => err.extend_from_slice(data),
        russh::ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
        _ => {}
    }
}
Ok(CommandOutput { stdout: out, stderr: err, exit_code: code.unwrap_or_default() })
```
`channel.wait()` → `Option<ChannelMsg>` (`None` al cerrar). No hace falta
implementar callbacks del Handler para leer output.

## Notas de seguridad para la implementación

- Structs que lleven la `SecretString` → `Debug` manual o no derivarlo;
  nunca `expose_secret()` en `tracing::*` ni en `SshError`.
- `SshError` sin `host`+credencial juntos ni contenido de clave;
  `Unreachable(String)` solo con host/motivo de red.
- Nunca un `check_server_key` que devuelva `Ok(true)` incondicional.
- `russh::client::Config` con timeouts de inactividad además del
  `tokio::time::timeout` de conexión.

## A verificar al implementar (docs.rs de la versión fijada)

- Tipo del parámetro de `check_server_key` (`PublicKeyOrCertificate` vs `&ssh_key::PublicKey`).
- Firma de `authenticate_publickey` (`PrivateKeyWithHashAlg`).
- Si `channel.exec` toma `(want_reply, cmd)`.

## Fuentes

- https://docs.rs/russh/latest/russh/
- https://docs.rs/russh/latest/russh/client/trait.Handler.html
- https://docs.rs/russh/latest/russh/enum.Error.html
- https://docs.rs/russh/latest/russh/keys/index.html
- https://docs.rs/async-ssh2-tokio/latest/async_ssh2_tokio/client/enum.ServerCheckMethod.html
- https://docs.rs/ssh-key/latest/ssh_key/enum.Fingerprint.html
- https://github.com/Eugeny/russh/discussions/304
