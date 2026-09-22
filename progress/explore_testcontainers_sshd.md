# Exploración: levantar sshd con `testcontainers` 0.24 para probar el cliente SSH (feature 4)

> Investigación del subagente Explore (2026-08-27), guardada por el leader
> (el Explore opera en solo-lectura). Revisó el código fuente de
> `testcontainers 0.24.0` vendido en `~/.cargo/registry`.

## 0. Estado del repo relevante

- `Cargo.toml`: `testcontainers = "0.24"` (dev-dep, sin features → **default = `["ring"]`**;
  NO están `blocking`, `http_wait`, `properties-config`, `reusable-containers`, `watchdog`).
  `tokio` es dep normal con `rt-multi-thread` + `macros` → `#[tokio::test]` funciona en `tests/`.
- `Cargo.lock` fija `testcontainers 0.24.0` (`bollard 0.18.1`).
- `tests/` está **vacío**. El archivo nuevo debe ser `tests/ssh.rs` (un archivo por módulo).
- `init.sh` corre `cargo test` (ignora `#[ignore]`) y `cargo test -- --ignored` (Docker).
  `cargo clippy --all-targets -- -D warnings` **incluye `tests/`** → código de test limpio de clippy/fmt.
  `#![deny(missing_docs)]` está solo en `lib.rs`, no aplica a `tests/`.
- `testcontainers-rs` 0.24 **no usa Ryuk**: borra contenedores en `Drop` vía API de Docker.
  No hace falta `TESTCONTAINERS_RYUK_DISABLED`.

## 1. API de `testcontainers` 0.24 — imports y tipos exactos

Re-exports en la raíz: `GenericImage`, `ContainerAsync`, `Image`, `ImageExt`,
`ContainerRequest`, `TestcontainersError`, `CopyDataSource`, `CopyToContainer`.
Bajo `testcontainers::core`: `WaitFor`, `ExecCommand`, `CmdWaitFor`, `ContainerPort`,
`IntoContainerPort`, `Mount`, `AccessMode`, `MountType`, `ContainerState`,
`ExitWaitStrategy`, `HealthWaitStrategy`.
Runner: `testcontainers::runners::AsyncRunner` (trait, aporta `.start()` y `.pull_image()`).

```rust
use std::time::Duration;

use testcontainers::{
    core::{IntoContainerPort, Mount, AccessMode, WaitFor, ExecCommand, CmdWaitFor},
    runners::AsyncRunner,
    GenericImage, ImageExt, ContainerAsync,
};
```

### Definir y arrancar una imagen

`GenericImage::new<S: Into<String>>(name: S, tag: S)` — **los dos argumentos son del mismo
tipo `S`** (usa dos `&str` literales; mezclar `String` + `&str` no infiere).

Métodos de `GenericImage` (builder, devuelven `GenericImage`) — **invocarlos ANTES que los de `ImageExt`**:
- `.with_wait_for(WaitFor) -> GenericImage`
- `.with_exposed_port(ContainerPort) -> GenericImage`
- `.with_entrypoint(&str) -> GenericImage`

Métodos de `ImageExt` (blanket impl; devuelven `ContainerRequest<I>`):
`.with_env_var(k, v)`, `.with_cmd(iter)`, `.with_mapped_port(host_port: u16, ContainerPort)`,
`.with_network(s)`, `.with_container_name(s)`, `.with_mount(impl Into<Mount>)`,
`.with_copy_to(target: impl Into<String>, source: impl Into<CopyDataSource>)`,
`.with_startup_timeout(Duration)` (default 60 s), `.with_privileged(bool)`, `.with_cap_add(s)`,
`.with_user(s)`, `.with_working_dir(s)`, `.with_log_consumer(...)`, `.with_host(k, v)`.

Arranque (trait `AsyncRunner`):
```rust
let container: ContainerAsync<GenericImage> = GenericImage::new("image", "tag")
    .with_exposed_port(2222.tcp())
    .with_wait_for(WaitFor::message_on_stdout("Server listening on"))
    .with_env_var("KEY", "value")
    .start()
    .await?;                       // Result<ContainerAsync<I>, TestcontainersError>
```

`ContainerAsync` implementa `Drop` → el contenedor se elimina al salir de scope.
**Mantener el binding vivo toda la duración del test** (no `let _ = ...`).
`TESTCONTAINERS_COMMAND=keep` lo deja vivo para depurar.

### Puertos

```rust
2222.tcp()            // ContainerPort::Tcp(2222)  (trait IntoContainerPort en scope)
ContainerPort::Tcp(2222)
```
`container.get_host_port_ipv4(impl Into<ContainerPort>) -> Result<u16>` — `2222u16` sirve.
Devuelve el puerto **aleatorio** que Docker asignó en el host. Hay `get_host_port_ipv6`.

`container.get_host() -> Result<url::Host>` — host donde alcanzar el contenedor
(`localhost` en local; IP del daemon si `DOCKER_HOST` es remoto). **Usar esto, no `127.0.0.1`.**

```rust
let host = container.get_host().await?.to_string();     // "localhost"
let port = container.get_host_port_ipv4(2222).await?;   // p.ej. 49173
```

### Wait strategies (`WaitFor`)

`enum WaitFor { Nothing, Log(LogWaitStrategy), Duration{length}, Healthcheck(HealthWaitStrategy), Http(..) /*feature http_wait, no disponible*/, Exit(ExitWaitStrategy) }`

- `WaitFor::message_on_stdout(impl AsRef<[u8]>)` ← el más usado
- `WaitFor::message_on_stderr(...)`
- `WaitFor::healthcheck()`
- `WaitFor::seconds(u64)` / `WaitFor::millis(u64)` (desaconsejado; solo fallback)
- `WaitFor::exit(ExitWaitStrategy::new().with_exit_code(0))`

`Http` **no disponible** (requiere feature `http_wait`); para sshd da igual.

Recomendación sshd: esperar el log de sshd escuchando + que el `connect()` del cliente
tenga timeout + un par de reintentos (carrera "puerto abierto pero sshd aún negociando").
Verificar el string exacto una vez con `container.stdout_to_vec().await`.

### Ejecutar comandos dentro del contenedor

```rust
let mut res = container
    .exec(ExecCommand::new(["sh", "-c", "chmod 0755 /usr/local/bin/nmap"]))
    .await?;
let code = res.exit_code().await?;                 // Option<i64>
let out  = String::from_utf8(res.stdout_to_vec().await?)?;
```
`ExecCommand::new(impl IntoIterator<Item = impl Into<String>>)`; opcional
`.with_cmd_ready_condition(CmdWaitFor::exit_code(0))`.

### Copiar ficheros al contenedor

1. `with_copy_to(target, source)` en construcción. `source: impl Into<CopyDataSource>`;
   hay `From` para `Vec<u8>` (→ `CopyDataSource::Data`) y `PathBuf`/`&Path` (→ `CopyDataSource::File`).
   **GOTCHA CRÍTICO 0.24:** al copiar bytes (`Data`), el crate fija el modo del fichero
   en el tar a **`0o644` hardcodeado** (`src/core/copy.rs::tar_bytes`) → **NO queda ejecutable**.
   Desde un `File` en disco sí se preserva el modo de origen.
2. `Mount::bind_mount(host_abs_path, container_path)` + `.with_access_mode(AccessMode::ReadOnly)`
   → `.with_mount(...)`. Preserva permisos. Requiere ruta **absoluta en el host del daemon**
   (rompe con `DOCKER_HOST` remoto; OK en local/CI con Docker local).

## 2. Qué imagen de sshd usar

| Imagen | Puerto | Config de auth | Pros | Contras |
|---|---|---|---|---|
| **`lscr.io/linuxserver/openssh-server`** (= `linuxserver/openssh-server`) | **2222** (no-root) | env: `USER_NAME`, `USER_PASSWORD` / `USER_PASSWORD_FILE`, `PASSWORD_ACCESS=true`, `PUBLIC_KEY` / `PUBLIC_KEY_FILE`, `SUDO_ACCESS=true`, `LOG_STDOUT=true` | Config declarativa por env. Multi-arch. Bien mantenida. `SUDO_ACCESS` ayuda a feature 5. | Puerto no estándar 2222. Arranque s6-overlay ~2-4 s. Regenerar host keys es incómodo (s6 relanza sshd). Imagen ~50 MB+. |
| **`testcontainers/sshd`** (`1.2.0`, `1.3.0`) | **22** | fijas: `root` / `Password123` | Minúscula, arranque rápido, determinista, log ready limpio (`Server listening on :: port 22.`). | Credenciales fijas; añadir usuarios/claves requiere `exec`. |
| **`panubo/sshd`** | 22 | `SSH_USERS=user:1000:1000`, `SSH_ENABLE_PASSWORD_AUTH=true`, montar `authorized_keys` | Alpine, pequeña, rápida, sshd en foreground. | No hay env para **fijar el password** → test password OK/malo engorroso. Orientada a clave. |
| `GenericImage` sobre alpine/debian + `apk/apt add openssh` | 22 | manual | Control total. | Lento y **flaky en CI**. `testcontainers` 0.24 **no construye imágenes**. Descartado. |

**Recomendación:**
- **Primario:** `lscr.io/linuxserver/openssh-server` con tag fijo (verificar un tag real; nunca `latest`).
  Cubre password auth (éxito/fallo), clave pública, `run_command` (`echo`), y `SUDO_ACCESS=true` para feature 5.
- **Alternativa ligera:** `testcontainers/sshd:1.3.0` (config por `exec`).

### Ejemplo: linuxserver/openssh-server con password + clave pública

```rust
const SSHD_IMAGE: &str = "lscr.io/linuxserver/openssh-server";
const SSHD_TAG: &str = "version-9.9_p2-r0"; // pinear a un tag real verificado
const SSH_PORT: u16 = 2222;

async fn start_sshd(username: &str, password: &str, authorized_pubkey: &str)
    -> Result<ContainerAsync<GenericImage>, TestcontainersError>
{
    GenericImage::new(SSHD_IMAGE, SSHD_TAG)
        .with_exposed_port(SSH_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Server listening on"))
        .with_env_var("PUID", "1000")
        .with_env_var("PGID", "1000")
        .with_env_var("TZ", "Etc/UTC")
        .with_env_var("USER_NAME", username)
        .with_env_var("USER_PASSWORD", password)
        .with_env_var("PASSWORD_ACCESS", "true")
        .with_env_var("SUDO_ACCESS", "true")            // feature 5 (nmap -O con sudo)
        .with_env_var("PUBLIC_KEY", authorized_pubkey)  // authorized_keys de una línea
        .with_env_var("LOG_STDOUT", "true")
        .start()
        .await
}
```

Verificar el string de "ready" real la primera vez con
`String::from_utf8(container.stdout_to_vec().await?)`. Si `Server listening on` no aparece,
usar `WaitFor::message_on_stdout("[ls.io-init] done.")` + reintentos en `connect()`.

### Test del comando remoto

`SshSession::run_command("echo hola")` → stdout `"hola\n"`, exit 0.
stderr / exit code: `run_command("sh -c 'echo err >&2; exit 3'")`.

## 3. Escenario "host key distinta / MITM" → `SshError::HostKeyMismatch`

Trait: `HostKeyStore { known_fingerprint(&self, host) -> Option<Fingerprint>; remember(&mut self, host, Fingerprint) }`
con impl **en memoria** para tests.

### Enfoque A (RECOMENDADO): pre-sembrar un fingerprint incorrecto

Un solo contenedor. El test siembra en el `HostKeyStore` en memoria un fingerprint que
**no** es el del contenedor y verifica que `connect()` devuelve `HostKeyMismatch`.

```rust
#[tokio::test]
#[ignore = "requiere Docker"]
async fn connect_rejects_changed_host_key_with_host_key_mismatch() {
    let c = start_sshd("scanuser", "s3cr3t", TEST_PUBKEY).await.unwrap();
    let host = c.get_host().await.unwrap().to_string();
    let port = c.get_host_port_ipv4(SSH_PORT).await.unwrap();

    let mut store = InMemoryHostKeyStore::new();
    store.remember(&target_key(&host, port), Fingerprint::sha256_from_raw([0x42; 32]));

    let err = ssh::connect_with_store(&host, port, "scanuser", creds("s3cr3t"), &mut store)
        .await
        .expect_err("debe rechazar host key cambiada");

    assert!(matches!(err, SshError::HostKeyMismatch { .. }));
}
```

Es exactamente el branch que pide el acceptance y no depende de reiniciar sshd ni puertos fijos.

### Enfoque B (contenedores secuenciales en puerto fijo)

Dos contenedores con host keys distintas, mapeados **secuencialmente** al **mismo puerto de
host fijo** con `with_mapped_port`, para que `host:port` (clave del store) sea idéntico.
Cada contenedor genera sus propias host keys al primer arranque. **Contra:** puerto de host
fijo → colisión → flaky; `drop(a)` es síncrono pero la eliminación es async-en-background
(ventana de puerto ocupado → añadir retry al `start()` de B).

### Enfoque C: regenerar host keys en el mismo contenedor — NO recomendado

Con linuxserver/s6 el reinicio de sshd es frágil; con imagen sshd en foreground matas PID 1.

**Conclusión:** **Enfoque A** para `HostKeyMismatch`; **B** solo si el revisor exige "dos
servidores reales". "Primera conexión guarda fingerprint" y "segunda lo acepta" → **un**
contenedor + `InMemoryHostKeyStore` vacío (`None` → `Some`, 2ª llamada coincide).

## 4. Stub de `nmap` falso en el contenedor (feature 5)

`scanner::run_scan` ejecuta `nmap ...` (y `sudo -n nmap ...` si `has_sudo`). El fake debe:
estar en `/usr/local/bin/nmap` (en PATH y en `secure_path` de sudo), ser **ejecutable**,
imprimir XML de nmap por stdout y respetar `-oX -`.

### Opción 1 (recomendada): `with_copy_to` bytes + `chmod` por `exec`

```rust
const FAKE_NMAP: &str = r#"#!/bin/sh
cat <<'XML'
<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="22"><state state="open"/>
      <service name="ssh" product="OpenSSH" version="9.6p1"/></port></ports>
  </host>
  <runstats><finished exit="success"/></runstats>
</nmaprun>
XML
"#;

let c = GenericImage::new(SSHD_IMAGE, SSHD_TAG)
    .with_wait_for(WaitFor::message_on_stdout("Server listening on"))
    .with_copy_to("/usr/local/bin/nmap", FAKE_NMAP.as_bytes().to_vec())
    .start().await?;

c.exec(ExecCommand::new(["chmod", "0755", "/usr/local/bin/nmap"])).await?; // OBLIGATORIO (0644 en 0.24)
```

- "nmap no instalado" (`ScanError::ToolNotAvailable`): no copiar el stub / `rm` el archivo.
- "sudo pide password" (`ScanError::InsufficientPrivileges`): arrancar sin `SUDO_ACCESS=true`
  (o stub `sudo` que devuelva 1) y pedir `has_sudo = true`.

### Opción 2: bind-mount de un fixture ejecutable versionado

`tests/fixtures/fake_nmap.sh` con bit de ejecución en git (`git update-index --chmod=+x`), y
`Mount::bind_mount(fixture_abs_path, "/usr/local/bin/nmap").with_access_mode(AccessMode::ReadOnly)`.
Sin `chmod`. Contra: ruta absoluta del host → no sirve con `DOCKER_HOST` remoto.

## 5. Docker no estándar (rootless / podman / remoto)

`testcontainers` 0.24 resuelve el host Docker en este orden (`src/core/env/config.rs`):
1. `tc.host` en `~/.testcontainers.properties` — requiere feature `properties-config`, **no habilitada** → ignorado.
2. **`DOCKER_HOST`** (env). `bollard` entiende `unix://`, `tcp://`, `http://`, `npipe://`.
3. `docker.host` del properties → ignorado.
4. `/var/run/docker.sock`.
5. Sockets rootless: `${XDG_RUNTIME_DIR}/.docker/run/docker.sock`, `${HOME}/.docker/run/docker.sock`, `${HOME}/.docker/desktop/docker.sock`.
6. Default `unix:///var/run/docker.sock`.

- **Docker rootless:** suele funcionar si `XDG_RUNTIME_DIR` está seteado (5.1). Si no:
  `export DOCKER_HOST=unix:///run/user/$(id -u)/docker.sock`.
- **Podman:** `systemctl --user start podman.socket` + `export DOCKER_HOST=unix:///run/user/$(id -u)/podman/podman.sock`.
  Con podman rootless los bind-mounts dan problemas de UID/SELinux → preferir `with_copy_to`.
- **Docker remoto TCP:** `DOCKER_HOST=tcp://host:2375` (+ `DOCKER_TLS_VERIFY=1`, `DOCKER_CERT_PATH`).
  Usar SIEMPRE `container.get_host().await?`; NO bind-mounts.
- Depuración: `TESTCONTAINERS_COMMAND=keep`; `RUST_LOG=testcontainers=debug`.

## 6. Esqueleto de `tests/ssh.rs`

```rust
use std::time::Duration;

use testcontainers::{
    core::{IntoContainerPort, WaitFor, ExecCommand},
    runners::AsyncRunner,
    GenericImage, ImageExt, ContainerAsync,
};

use nmap_service::ssh::{self, SshError};

const SSHD_IMAGE: &str = "lscr.io/linuxserver/openssh-server";
const SSHD_TAG: &str = "version-9.9_p2-r0";
const SSH_PORT: u16 = 2222;
const USER: &str = "scanuser";
const PASS: &str = "s3cr3t-test";

async fn sshd() -> ContainerAsync<GenericImage> {
    GenericImage::new(SSHD_IMAGE, SSHD_TAG)
        .with_exposed_port(SSH_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Server listening on"))
        .with_startup_timeout(Duration::from_secs(120))
        .with_env_var("PUID", "1000")
        .with_env_var("PGID", "1000")
        .with_env_var("TZ", "Etc/UTC")
        .with_env_var("USER_NAME", USER)
        .with_env_var("USER_PASSWORD", PASS)
        .with_env_var("PASSWORD_ACCESS", "true")
        .with_env_var("SUDO_ACCESS", "true")
        .with_env_var("LOG_STDOUT", "true")
        .start()
        .await
        .expect("sshd container up")
}

async fn endpoint(c: &ContainerAsync<GenericImage>) -> (String, u16) {
    let host = c.get_host().await.unwrap().to_string();
    let port = c.get_host_port_ipv4(SSH_PORT).await.unwrap();
    (host, port)
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn connect_succeeds_with_valid_password() {
    let c = sshd().await;
    let (host, port) = endpoint(&c).await;
    let session = ssh::connect(&host, port, USER, PASS).await.unwrap();
    let out = session.run_command("echo hola-mundo").await.unwrap();
    assert_eq!(out.stdout, "hola-mundo\n");
    assert_eq!(out.exit_code, 0);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn connect_fails_with_wrong_password() {
    let c = sshd().await;
    let (host, port) = endpoint(&c).await;
    let err = ssh::connect(&host, port, USER, "password-incorrecta").await.unwrap_err();
    assert!(matches!(err, SshError::AuthFailed));
}
// + tofu_first_connection_stores_fingerprint_second_accepts
// + connect_rejects_changed_host_key  (Enfoque A de §3)
```

## 7. Nota sobre el crate SSH (condiciona los tests)

No hay crate SSH en `Cargo.toml`. Ver `progress/explore_ssh_crate.md` → **`russh`**
(puro Rust, async/tokio). El `HostKeyMismatch` se observa vía
`client::Handler::check_server_key`; el fingerprint guardado en `HostKeyStore` es el
SHA256 de la clave pública del host (`key.fingerprint(HashAlg::Sha256)` → `SHA256:base64`).

## 8. Checklist de gotchas para el implementer

1. Mantener vivo el `ContainerAsync` toda la duración del test (no `let _`).
2. `GenericImage::new("a", "b")`: los dos args del mismo tipo.
3. Métodos de `GenericImage` **antes** que los de `ImageExt`.
4. Traer `IntoContainerPort` al scope para `.tcp()`.
5. Usar `get_host()` + `get_host_port_ipv4()`, nunca `127.0.0.1` fijo ni el puerto interno.
6. `with_copy_to` con bytes → archivo **0644**, `chmod` por `exec` si debe ejecutarse.
7. Pinear el tag de la imagen; pull 1ª vez lento → `with_startup_timeout(120s)`.
8. Verificar el string real del log de "ready" con `stdout_to_vec()`.
9. `cargo clippy --all-targets -D warnings` cubre `tests/ssh.rs`. `unwrap()`/`expect()` en tests permitidos.
10. Todos los tests con `#[ignore = "requiere Docker"]` y `#[tokio::test]`.
11. Puerto de host fijo (`with_mapped_port`) solo si es imprescindible (Enfoque B).
