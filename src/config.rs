//! Carga y validación de la configuración del servicio desde variables de
//! entorno (URI de MongoDB, colas SQS y topic SNS, timeouts SSH).
//!
//! La lectura del entorno del proceso ([`Config::from_env`]) se separa de la
//! lógica de validación (`Config::from_source`, privada) para poder testear
//! esta última con un mapa inyectado, sin mutar variables de entorno globales
//! del proceso ni depender del orden de ejecución de los tests.

use std::time::Duration;

use secrecy::SecretString;

use crate::scanner::Timing;

/// Nombre de la variable de entorno con la URI de conexión a MongoDB (`db-nmap`).
pub const MONGO_URI_VAR: &str = "MS_NMAP_MONGO_URI";

/// Nombre de la variable de entorno con el nombre de la base de datos de MongoDB
/// que usa el servicio (`repository::MongoRepository::connect`).
pub const MONGO_DB_VAR: &str = "MS_NMAP_MONGO_DB";

/// Nombre de la variable de entorno con el puerto SSH del objetivo.
///
/// El `ScanRequest` no transporta el puerto SSH: es configuración del despliegue
/// (todos los objetivos de un mismo entorno escuchan SSH en el mismo puerto).
/// Se expresa como un entero `1..=65535`.
pub const SSH_PORT_VAR: &str = "MS_NMAP_SSH_PORT";

/// Nombre de la variable de entorno con el timeout de establecimiento de la
/// conexión SSH, expresado en segundos enteros.
pub const SSH_CONNECT_TIMEOUT_VAR: &str = "MS_NMAP_SSH_CONNECT_TIMEOUT_SECS";

/// Nombre de la variable de entorno con el timeout de ejecución de un comando
/// remoto sobre la sesión SSH, expresado en segundos enteros.
pub const SSH_COMMAND_TIMEOUT_VAR: &str = "MS_NMAP_SSH_COMMAND_TIMEOUT_SECS";

/// Nombre de la variable de entorno con la ruta al CSV de Exploit-DB
/// (`files_exploits.csv`) que usa [`crate::enrichment::ExploitDbEnricher`].
///
/// No tiene valor por defecto: el enriquecimiento offline es una capacidad
/// obligatoria del servicio y el CSV se bundlea en la imagen (el `Dockerfile`
/// fija esta variable con `ENV`).
pub const EXPLOITDB_CSV_VAR: &str = "MS_NMAP_EXPLOITDB_CSV";

/// Nombre de la variable de entorno que habilita (o no) el enriquecimiento
/// online contra la API NVD 2.0 ([`crate::enrichment::NvdApiEnricher`]).
///
/// Es **egress opt-in**: requerida, sin valor por defecto, y su valor debe ser
/// exactamente `"true"` o `"false"`. Si es `"false"`, [`crate::wiring`] no
/// añade el adaptador NVD al composite y el servicio no hace ninguna llamada
/// de red hacia `services.nvd.nist.gov` (ver `docs/security-scope.md`).
pub const NVD_ENRICHMENT_ENABLED_VAR: &str = "MS_NMAP_NVD_ENRICHMENT_ENABLED";

/// Nombre de la variable de entorno con la API key de NVD.
///
/// Genuinamente **opcional**: la propia API NVD 2.0 trata la key como
/// opcional (sube el límite de tasa permitido, pero funciona sin ella). Vacía
/// o ausente se interpreta como "sin autenticar", nunca como error.
pub const NVD_API_KEY_VAR: &str = "MS_NMAP_NVD_API_KEY";

/// Nombre de la variable de entorno con el TTL (segundos) de la caché
/// persistente de hallazgos de NVD ([`crate::repository::MongoNvdCache`]).
///
/// Sólo es requerida si [`NVD_ENRICHMENT_ENABLED_VAR`] es `"true"`; si el
/// enriquecimiento NVD está deshabilitado no se exige (ni se lee su valor).
pub const NVD_CACHE_TTL_VAR: &str = "MS_NMAP_NVD_CACHE_TTL_SECS";

/// Nombre de la variable de entorno opcional con la plantilla de temporización
/// (`-T`) que usa [`crate::scanner::run_scan`] (vía [`crate::scanner::ScanOptions`]).
///
/// Acepta exactamente `"polite"`, `"normal"` o `"aggressive"`, mapeando a
/// [`Timing::Polite`] (`-T2`), [`Timing::Normal`] (`-T3`) y
/// [`Timing::Aggressive`] (`-T4`) respectivamente. Es un knob **operativo**
/// para pruebas/demos (acelerar un escaneo sin recompilar, ver
/// `docs/security-scope.md`): si está ausente, el default sigue siendo
/// exactamente el actual ([`Timing::Polite`]), sin cambio de comportamiento
/// para quien no la configure. No afecta en absoluto a `detection_flags`
/// (`-sV --script vuln`), que permanece hardcodeado y fuera del alcance de
/// esta variable.
pub const SCAN_TIMING_VAR: &str = "MS_NMAP_SCAN_TIMING";

/// Nombre de la variable de entorno con la región AWS de SQS/SNS. Requerida.
pub const AWS_REGION_VAR: &str = "AWS_REGION";

/// Nombre de la variable de entorno opcional con el endpoint AWS alternativo
/// (sólo LocalStack/desarrollo). Ausente en AWS real.
pub const AWS_ENDPOINT_URL_VAR: &str = "AWS_ENDPOINT_URL";

/// Nombre de la variable de entorno con la URL de la cola SQS de solicitudes
/// de escaneo.
pub const SCAN_REQUESTS_QUEUE_URL_VAR: &str = "MS_NMAP_SCAN_REQUESTS_QUEUE_URL";

/// Nombre de la variable de entorno con la URL de la cola SQS de cancelaciones.
pub const SCAN_CANCELLATIONS_QUEUE_URL_VAR: &str = "MS_NMAP_SCAN_CANCELLATIONS_QUEUE_URL";

/// Nombre de la variable de entorno con la URL de la DLQ de solicitudes.
pub const SCAN_REQUESTS_DLQ_URL_VAR: &str = "MS_NMAP_SCAN_REQUESTS_DLQ_URL";

/// Nombre de la variable de entorno con la URL de la DLQ de cancelaciones.
pub const SCAN_CANCELLATIONS_DLQ_URL_VAR: &str = "MS_NMAP_SCAN_CANCELLATIONS_DLQ_URL";

/// Nombre de la variable de entorno con el ARN del topic SNS de desenlaces.
pub const SCAN_OUTCOMES_TOPIC_ARN_VAR: &str = "MS_NMAP_SCAN_OUTCOMES_TOPIC_ARN";

/// Errores posibles al construir la [`Config`] del servicio.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Falta una variable de entorno requerida. Contiene el nombre de la variable.
    #[error("falta la variable de entorno requerida: {0}")]
    MissingVar(&'static str),

    /// Una variable está presente pero su valor no es válido.
    #[error("valor inválido para {var}: {reason}")]
    InvalidValue {
        /// Nombre de la variable de entorno con el valor inválido.
        var: &'static str,
        /// Descripción legible de por qué el valor es inválido (nunca incluye
        /// el contenido de una credencial).
        reason: String,
    },

    /// Una variable URL está presente pero no se puede parsear.
    #[error("URL inválida en {var}: {source}")]
    InvalidUrl {
        /// Nombre de la variable de entorno con la URL inválida.
        var: &'static str,
        /// Error de parseo subyacente.
        source: url::ParseError,
    },

    /// Una variable ARN no tiene la forma esperada. No incluye el valor.
    #[error(
        "ARN de topic SNS inválido en {var}: se esperaba \
         arn:<partición>:sns:<región>:<cuenta de 12 dígitos>:<nombre>"
    )]
    InvalidArn {
        /// Nombre de la variable de entorno con el ARN inválido.
        var: &'static str,
    },
}

/// Configuración validada del servicio `ms-nmap`.
///
/// Se construye una sola vez al arrancar con [`Config::from_env`]. Todos sus
/// valores provienen del entorno; el código no hardcodea URIs, endpoints ni
/// timeouts de negocio.
///
/// Los secretos ([`Config::nvd_api_key`]) son [`SecretString`]: su contenido
/// se redacta al formatear la struct con `Debug`, de modo que no pueden
/// filtrarse por accidente vía `tracing::debug!`/`error!` ni en un panic. Las
/// credenciales de AWS no pasan por aquí: salen de la cadena de proveedores por
/// defecto del SDK (rol de la tarea ECS).
#[derive(Debug)]
pub struct Config {
    /// URI de conexión a MongoDB (`db-nmap`).
    pub mongo_uri: String,
    /// Nombre de la base de datos de MongoDB que usa el servicio.
    pub mongo_db: String,
    /// Puerto SSH del objetivo (`1..=65535`).
    pub ssh_port: u16,
    /// Timeout para establecer la conexión SSH con el objetivo.
    pub ssh_connect_timeout: Duration,
    /// Timeout para la ejecución de un comando remoto sobre la sesión SSH.
    pub ssh_command_timeout: Duration,
    /// Ruta al CSV de Exploit-DB (`files_exploits.csv`) para el enriquecimiento
    /// offline de vulnerabilidades.
    pub exploitdb_csv: String,
    /// Si el enriquecimiento online contra la API NVD 2.0 está habilitado.
    /// Egress opt-in: si es `false`, [`crate::wiring`] no construye el
    /// adaptador NVD y no hay llamadas de red.
    pub nvd_enrichment_enabled: bool,
    /// API key de NVD. Genuinamente opcional: `None` si está ausente o vacía.
    /// Contenido redactado en `Debug`.
    pub nvd_api_key: Option<SecretString>,
    /// TTL de la caché persistente de hallazgos de NVD. `Some` sólo si
    /// [`Config::nvd_enrichment_enabled`] es `true` (en ese caso es
    /// obligatorio); `None` si el enriquecimiento NVD está deshabilitado.
    pub nvd_cache_ttl: Option<Duration>,
    /// Plantilla de temporización (`-T`) elegida para el escaneo. Ver
    /// [`SCAN_TIMING_VAR`]. Default (variable ausente): [`Timing::Polite`].
    pub scan_timing: Timing,
    /// Región AWS usada por los clientes SQS/SNS. Ver [`AWS_REGION_VAR`].
    pub aws_region: String,
    /// Endpoint AWS alternativo (sólo LocalStack). `None` en AWS real. Ver
    /// [`AWS_ENDPOINT_URL_VAR`].
    pub aws_endpoint_url: Option<url::Url>,
    /// URL de la cola SQS de solicitudes de escaneo.
    pub scan_requests_queue_url: url::Url,
    /// URL de la cola SQS de cancelaciones de escaneo.
    pub scan_cancellations_queue_url: url::Url,
    /// URL de la DLQ de solicitudes de escaneo.
    pub scan_requests_dlq_url: url::Url,
    /// URL de la DLQ de cancelaciones de escaneo.
    pub scan_cancellations_dlq_url: url::Url,
    /// ARN del topic SNS donde se publican los desenlaces de escaneo.
    pub scan_outcomes_topic_arn: String,
}

impl Config {
    /// Construye la configuración leyendo las variables de entorno del proceso.
    ///
    /// # Errores
    ///
    /// - [`ConfigError::MissingVar`] si falta (o está vacía) una variable
    ///   requerida: [`MONGO_URI_VAR`], [`MONGO_DB_VAR`], [`SSH_PORT_VAR`],
    ///   [`SSH_CONNECT_TIMEOUT_VAR`],
    ///   [`SSH_COMMAND_TIMEOUT_VAR`], [`EXPLOITDB_CSV_VAR`],
    ///   [`NVD_ENRICHMENT_ENABLED_VAR`], o [`NVD_CACHE_TTL_VAR`] cuando
    ///   [`NVD_ENRICHMENT_ENABLED_VAR`] es `"true"`; y las variables SQS/SNS
    ///   [`AWS_REGION_VAR`], [`SCAN_REQUESTS_QUEUE_URL_VAR`],
    ///   [`SCAN_CANCELLATIONS_QUEUE_URL_VAR`], [`SCAN_REQUESTS_DLQ_URL_VAR`],
    ///   [`SCAN_CANCELLATIONS_DLQ_URL_VAR`] y [`SCAN_OUTCOMES_TOPIC_ARN_VAR`].
    /// - [`ConfigError::InvalidUrl`] si una URL de cola o [`AWS_ENDPOINT_URL_VAR`]
    ///   (opcional) no se puede parsear.
    /// - [`ConfigError::InvalidArn`] si [`SCAN_OUTCOMES_TOPIC_ARN_VAR`] no es un
    ///   ARN de topic SNS (el error no incluye el valor).
    /// - [`ConfigError::InvalidValue`] si un timeout está presente pero no es
    ///   un entero de segundos positivo, si [`SSH_PORT_VAR`] no es un entero en
    ///   el rango `1..=65535`, si [`NVD_ENRICHMENT_ENABLED_VAR`] no es
    ///   exactamente `"true"` o `"false"`, o si [`SCAN_TIMING_VAR`] (opcional)
    ///   está presente pero no es exactamente `"polite"`, `"normal"` o
    ///   `"aggressive"`.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_source(|key| std::env::var(key).ok())
    }

    /// Igual que [`Config::from_env`] pero tomando los valores de una función
    /// de búsqueda arbitraria. Permite testear la validación sin tocar el
    /// entorno global del proceso.
    fn from_source<F>(lookup: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let mongo_uri = required(MONGO_URI_VAR, lookup(MONGO_URI_VAR))?;
        let mongo_db = required(MONGO_DB_VAR, lookup(MONGO_DB_VAR))?;
        let ssh_port = parse_port(SSH_PORT_VAR, lookup(SSH_PORT_VAR))?;

        let ssh_connect_timeout =
            parse_timeout(SSH_CONNECT_TIMEOUT_VAR, lookup(SSH_CONNECT_TIMEOUT_VAR))?;
        let ssh_command_timeout =
            parse_timeout(SSH_COMMAND_TIMEOUT_VAR, lookup(SSH_COMMAND_TIMEOUT_VAR))?;
        let exploitdb_csv = required(EXPLOITDB_CSV_VAR, lookup(EXPLOITDB_CSV_VAR))?;

        let nvd_enrichment_enabled = parse_strict_bool(
            NVD_ENRICHMENT_ENABLED_VAR,
            lookup(NVD_ENRICHMENT_ENABLED_VAR),
        )?;
        let nvd_api_key = optional_secret(lookup(NVD_API_KEY_VAR));
        let nvd_cache_ttl = if nvd_enrichment_enabled {
            Some(parse_timeout(NVD_CACHE_TTL_VAR, lookup(NVD_CACHE_TTL_VAR))?)
        } else {
            None
        };
        let scan_timing = parse_timing(SCAN_TIMING_VAR, lookup(SCAN_TIMING_VAR))?;
        let aws_region = required(AWS_REGION_VAR, lookup(AWS_REGION_VAR))?;
        let aws_endpoint_url = optional_url(AWS_ENDPOINT_URL_VAR, lookup(AWS_ENDPOINT_URL_VAR))?;
        let scan_requests_queue_url = required_url(
            SCAN_REQUESTS_QUEUE_URL_VAR,
            lookup(SCAN_REQUESTS_QUEUE_URL_VAR),
        )?;
        let scan_cancellations_queue_url = required_url(
            SCAN_CANCELLATIONS_QUEUE_URL_VAR,
            lookup(SCAN_CANCELLATIONS_QUEUE_URL_VAR),
        )?;
        let scan_requests_dlq_url =
            required_url(SCAN_REQUESTS_DLQ_URL_VAR, lookup(SCAN_REQUESTS_DLQ_URL_VAR))?;
        let scan_cancellations_dlq_url = required_url(
            SCAN_CANCELLATIONS_DLQ_URL_VAR,
            lookup(SCAN_CANCELLATIONS_DLQ_URL_VAR),
        )?;
        let scan_outcomes_topic_arn = required_sns_topic_arn(
            SCAN_OUTCOMES_TOPIC_ARN_VAR,
            lookup(SCAN_OUTCOMES_TOPIC_ARN_VAR),
        )?;

        Ok(Self {
            mongo_uri,
            mongo_db,
            ssh_port,
            ssh_connect_timeout,
            ssh_command_timeout,
            exploitdb_csv,
            nvd_enrichment_enabled,
            nvd_api_key,
            nvd_cache_ttl,
            scan_timing,
            aws_region,
            aws_endpoint_url,
            scan_requests_queue_url,
            scan_cancellations_queue_url,
            scan_requests_dlq_url,
            scan_cancellations_dlq_url,
            scan_outcomes_topic_arn,
        })
    }
}

fn required(var: &'static str, raw: Option<String>) -> Result<String, ConfigError> {
    match raw {
        Some(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(ConfigError::MissingVar(var)),
    }
}

fn parse_url(var: &'static str, value: &str) -> Result<url::Url, ConfigError> {
    url::Url::parse(value.trim()).map_err(|source| ConfigError::InvalidUrl { var, source })
}

fn required_url(var: &'static str, raw: Option<String>) -> Result<url::Url, ConfigError> {
    parse_url(var, &required(var, raw)?)
}

/// Variable URL genuinamente opcional: ausente o vacía es `None`.
fn optional_url(var: &'static str, raw: Option<String>) -> Result<Option<url::Url>, ConfigError> {
    raw.filter(|v| !v.trim().is_empty())
        .map(|v| parse_url(var, &v))
        .transpose()
}

fn required_sns_topic_arn(var: &'static str, raw: Option<String>) -> Result<String, ConfigError> {
    let value = required(var, raw)?;
    if is_sns_topic_arn(value.trim()) {
        Ok(value.trim().to_owned())
    } else {
        Err(ConfigError::InvalidArn { var })
    }
}

/// `true` si `value` es `arn:<partición>:sns:<región>:<cuenta de 12 dígitos>:<nombre>`.
fn is_sns_topic_arn(value: &str) -> bool {
    let parts: Vec<&str> = value.split(':').collect();
    let [arn, partition, service, region, account, name] = parts.as_slice() else {
        return false;
    };
    *arn == "arn"
        && !partition.is_empty()
        && *service == "sns"
        && !region.is_empty()
        && account.len() == 12
        && account.bytes().all(|b| b.is_ascii_digit())
        && !name.is_empty()
}

fn parse_port(var: &'static str, raw: Option<String>) -> Result<u16, ConfigError> {
    let Some(value) = raw.filter(|v| !v.trim().is_empty()) else {
        return Err(ConfigError::MissingVar(var));
    };

    let port: u16 = value
        .trim()
        .parse()
        .map_err(|_| ConfigError::InvalidValue {
            var,
            reason: format!("se esperaba un puerto TCP en 1..=65535, se recibió {value:?}"),
        })?;

    if port == 0 {
        return Err(ConfigError::InvalidValue {
            var,
            reason: "el puerto debe estar en el rango 1..=65535".to_owned(),
        });
    }

    Ok(port)
}

fn parse_timeout(var: &'static str, raw: Option<String>) -> Result<Duration, ConfigError> {
    let Some(value) = raw.filter(|v| !v.trim().is_empty()) else {
        return Err(ConfigError::MissingVar(var));
    };

    let secs: u64 = value
        .trim()
        .parse()
        .map_err(|_| ConfigError::InvalidValue {
            var,
            reason: format!("se esperaba un entero de segundos, se recibió {value:?}"),
        })?;

    if secs == 0 {
        return Err(ConfigError::InvalidValue {
            var,
            reason: "el timeout debe ser mayor que cero".to_owned(),
        });
    }

    Ok(Duration::from_secs(secs))
}

/// Parsea una variable booleana requerida cuyo valor debe ser exactamente
/// `"true"` o `"false"` (sin `"1"`/`"0"`/mayúsculas ni ningún otro alias): una
/// variable de egress opt-in como [`NVD_ENRICHMENT_ENABLED_VAR`] no debe
/// tener ambigüedad sobre qué valor la activa.
fn parse_strict_bool(var: &'static str, raw: Option<String>) -> Result<bool, ConfigError> {
    let value = required(var, raw)?;
    match value.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(ConfigError::InvalidValue {
            var,
            reason: format!("se esperaba \"true\" o \"false\", se recibió {other:?}"),
        }),
    }
}

/// Lee una variable genuinamente opcional como [`SecretString`]: ausente o
/// vacía (tras `trim`) es `None`, sin error; cualquier otro valor es `Some`.
fn optional_secret(raw: Option<String>) -> Option<SecretString> {
    raw.filter(|value| !value.trim().is_empty())
        .map(SecretString::from)
}

/// Parsea [`SCAN_TIMING_VAR`]: variable genuinamente opcional (ausente o
/// vacía, tras `trim`, es el default [`Timing::Polite`]) cuyo valor, si está
/// presente, debe ser exactamente `"polite"`, `"normal"` o `"aggressive"`.
fn parse_timing(var: &'static str, raw: Option<String>) -> Result<Timing, ConfigError> {
    let Some(value) = raw.filter(|v| !v.trim().is_empty()) else {
        return Ok(Timing::Polite);
    };

    match value.trim() {
        "polite" => Ok(Timing::Polite),
        "normal" => Ok(Timing::Normal),
        "aggressive" => Ok(Timing::Aggressive),
        other => Err(ConfigError::InvalidValue {
            var,
            reason: format!(
                "se esperaba \"polite\", \"normal\" o \"aggressive\", se recibió {other:?}"
            ),
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use secrecy::ExposeSecret;

    use super::*;

    const VALID_REQUESTS_QUEUE_URL: &str =
        "https://sqs.us-east-1.amazonaws.com/123456789012/ms-nmap-scan-requests";
    const VALID_CANCELLATIONS_QUEUE_URL: &str =
        "https://sqs.us-east-1.amazonaws.com/123456789012/ms-nmap-scan-cancellations";
    const VALID_REQUESTS_DLQ_URL: &str =
        "https://sqs.us-east-1.amazonaws.com/123456789012/ms-nmap-scan-requests-dlq";
    const VALID_CANCELLATIONS_DLQ_URL: &str =
        "https://sqs.us-east-1.amazonaws.com/123456789012/ms-nmap-scan-cancellations-dlq";
    const VALID_OUTCOMES_TOPIC_ARN: &str = "arn:aws:sns:us-east-1:123456789012:scan-outcomes";
    const NEW_REQUIRED_VARS: [&str; 6] = [
        AWS_REGION_VAR,
        SCAN_REQUESTS_QUEUE_URL_VAR,
        SCAN_CANCELLATIONS_QUEUE_URL_VAR,
        SCAN_REQUESTS_DLQ_URL_VAR,
        SCAN_CANCELLATIONS_DLQ_URL_VAR,
        SCAN_OUTCOMES_TOPIC_ARN_VAR,
    ];

    fn valid_vars() -> HashMap<&'static str, &'static str> {
        HashMap::from([
            (MONGO_URI_VAR, "mongodb://db-nmap:27017/nmap"),
            (MONGO_DB_VAR, "db-nmap"),
            (SSH_PORT_VAR, "22"),
            (SSH_CONNECT_TIMEOUT_VAR, "7"),
            (SSH_COMMAND_TIMEOUT_VAR, "120"),
            (EXPLOITDB_CSV_VAR, "/opt/exploitdb/files_exploits.csv"),
            (NVD_ENRICHMENT_ENABLED_VAR, "false"),
            (AWS_REGION_VAR, "us-east-1"),
            (SCAN_REQUESTS_QUEUE_URL_VAR, VALID_REQUESTS_QUEUE_URL),
            (
                SCAN_CANCELLATIONS_QUEUE_URL_VAR,
                VALID_CANCELLATIONS_QUEUE_URL,
            ),
            (SCAN_REQUESTS_DLQ_URL_VAR, VALID_REQUESTS_DLQ_URL),
            (SCAN_CANCELLATIONS_DLQ_URL_VAR, VALID_CANCELLATIONS_DLQ_URL),
            (SCAN_OUTCOMES_TOPIC_ARN_VAR, VALID_OUTCOMES_TOPIC_ARN),
        ])
    }

    fn config_from(vars: &HashMap<&'static str, &'static str>) -> Result<Config, ConfigError> {
        Config::from_source(|key| vars.get(key).map(|v| (*v).to_owned()))
    }

    #[test]
    fn loads_valid_config_with_expected_parsed_values() {
        let config = config_from(&valid_vars()).expect("la config válida debe cargar");

        assert_eq!(config.mongo_uri, "mongodb://db-nmap:27017/nmap");
        assert_eq!(config.mongo_db, "db-nmap");
        assert_eq!(config.ssh_port, 22);
        assert_eq!(config.ssh_connect_timeout, Duration::from_secs(7));
        assert_eq!(config.ssh_command_timeout, Duration::from_secs(120));
        assert_eq!(config.exploitdb_csv, "/opt/exploitdb/files_exploits.csv");
        assert!(!config.nvd_enrichment_enabled);
        assert!(config.nvd_api_key.is_none());
        assert!(config.nvd_cache_ttl.is_none());
        assert_eq!(config.scan_timing, Timing::Polite);
    }

    #[test]
    fn missing_scan_timing_var_defaults_to_polite() {
        let vars = valid_vars();
        // Sin SCAN_TIMING_VAR.

        let config = config_from(&vars).expect("sin MS_NMAP_SCAN_TIMING debe cargar igual");

        assert_eq!(config.scan_timing, Timing::Polite);
    }

    #[test]
    fn scan_timing_var_normal_maps_to_timing_normal() {
        let mut vars = valid_vars();
        vars.insert(SCAN_TIMING_VAR, "normal");

        let config = config_from(&vars).expect("\"normal\" debe cargar");

        assert_eq!(config.scan_timing, Timing::Normal);
    }

    #[test]
    fn scan_timing_var_aggressive_maps_to_timing_aggressive() {
        let mut vars = valid_vars();
        vars.insert(SCAN_TIMING_VAR, "aggressive");

        let config = config_from(&vars).expect("\"aggressive\" debe cargar");

        assert_eq!(config.scan_timing, Timing::Aggressive);
    }

    #[test]
    fn scan_timing_var_rejects_invalid_values() {
        for bad in ["T4", "AGGRESSIVE", "insane", ""] {
            let mut vars = valid_vars();
            vars.insert(SCAN_TIMING_VAR, bad);

            if bad.is_empty() {
                let config = config_from(&vars).expect("vacío se trata como ausente");
                assert_eq!(config.scan_timing, Timing::Polite);
                continue;
            }

            let err = config_from(&vars).expect_err(&format!("{bad:?} no es un timing válido"));

            match err {
                ConfigError::InvalidValue { var, .. } => assert_eq!(var, SCAN_TIMING_VAR),
                other => {
                    panic!("valor {bad:?}: se esperaba InvalidValue, se obtuvo {other:?}")
                }
            }
        }
    }

    #[test]
    fn nvd_enabled_without_cache_ttl_is_a_typed_error() {
        let mut vars = valid_vars();
        vars.insert(NVD_ENRICHMENT_ENABLED_VAR, "true");
        // Sin NVD_CACHE_TTL_VAR.

        let err = config_from(&vars).expect_err("NVD habilitado sin TTL de caché debe fallar");

        assert!(matches!(err, ConfigError::MissingVar(NVD_CACHE_TTL_VAR)));
    }

    #[test]
    fn nvd_enabled_with_cache_ttl_loads_ok() {
        let mut vars = valid_vars();
        vars.insert(NVD_ENRICHMENT_ENABLED_VAR, "true");
        vars.insert(NVD_CACHE_TTL_VAR, "86400");

        let config = config_from(&vars).expect("NVD habilitado con TTL debe cargar");

        assert!(config.nvd_enrichment_enabled);
        assert_eq!(config.nvd_cache_ttl, Some(Duration::from_secs(86400)));
    }

    #[test]
    fn nvd_disabled_without_cache_ttl_or_api_key_loads_ok() {
        let mut vars = valid_vars();
        vars.insert(NVD_ENRICHMENT_ENABLED_VAR, "false");
        // Sin NVD_CACHE_TTL_VAR ni NVD_API_KEY_VAR: no se exigen deshabilitado.

        let config = config_from(&vars).expect("NVD deshabilitado no exige TTL ni API key");

        assert!(!config.nvd_enrichment_enabled);
        assert!(config.nvd_cache_ttl.is_none());
        assert!(config.nvd_api_key.is_none());
    }

    #[test]
    fn nvd_enrichment_enabled_var_rejects_non_boolean_values() {
        for bad in ["1", "yes", "TRUE", ""] {
            let mut vars = valid_vars();
            vars.insert(NVD_ENRICHMENT_ENABLED_VAR, bad);

            let err = config_from(&vars).expect_err(&format!("{bad:?} no es un booleano válido"));

            match (bad, err) {
                ("", ConfigError::MissingVar(NVD_ENRICHMENT_ENABLED_VAR)) => {}
                (_, ConfigError::InvalidValue { var, .. }) => {
                    assert_eq!(var, NVD_ENRICHMENT_ENABLED_VAR)
                }
                (bad, other) => {
                    panic!("valor {bad:?}: se esperaba error tipado, se obtuvo {other:?}")
                }
            }
        }
    }

    #[test]
    fn missing_nvd_enrichment_enabled_var_yields_typed_missing_var_error() {
        let mut vars = valid_vars();
        vars.remove(NVD_ENRICHMENT_ENABLED_VAR);

        let err = config_from(&vars).expect_err("sin NVD_ENRICHMENT_ENABLED debe fallar");

        assert!(matches!(
            err,
            ConfigError::MissingVar(NVD_ENRICHMENT_ENABLED_VAR)
        ));
    }

    #[test]
    fn empty_nvd_api_key_is_none() {
        let mut vars = valid_vars();
        vars.insert(NVD_API_KEY_VAR, "   ");

        let config = config_from(&vars).expect("API key vacía no debe fallar la carga");

        assert!(config.nvd_api_key.is_none());
    }

    #[test]
    fn present_nvd_api_key_is_some() {
        let mut vars = valid_vars();
        vars.insert(NVD_API_KEY_VAR, "abc123-api-key");

        let config = config_from(&vars).expect("config válida");

        assert_eq!(
            config
                .nvd_api_key
                .expect("API key presente debe ser Some")
                .expose_secret(),
            "abc123-api-key"
        );
    }

    #[test]
    fn missing_exploitdb_csv_var_yields_typed_missing_var_error() {
        let mut vars = valid_vars();
        vars.remove(EXPLOITDB_CSV_VAR);

        let err = config_from(&vars).expect_err("sin EXPLOITDB_CSV debe fallar");

        assert!(matches!(err, ConfigError::MissingVar(EXPLOITDB_CSV_VAR)));
    }

    #[test]
    fn empty_exploitdb_csv_var_is_treated_as_missing() {
        let mut vars = valid_vars();
        vars.insert(EXPLOITDB_CSV_VAR, "   ");

        let err = config_from(&vars).expect_err("EXPLOITDB_CSV vacía debe fallar");

        assert!(matches!(err, ConfigError::MissingVar(EXPLOITDB_CSV_VAR)));
    }

    #[test]
    fn missing_required_var_yields_typed_missing_var_error() {
        let mut vars = valid_vars();
        vars.remove(MONGO_URI_VAR);

        let err = config_from(&vars).expect_err("sin MONGO_URI debe fallar");

        assert!(matches!(err, ConfigError::MissingVar(MONGO_URI_VAR)));
    }

    #[test]
    fn empty_required_var_is_treated_as_missing() {
        let mut vars = valid_vars();
        vars.insert(MONGO_URI_VAR, "   ");

        let err = config_from(&vars).expect_err("URI vacía debe fallar");

        assert!(matches!(err, ConfigError::MissingVar(MONGO_URI_VAR)));
    }

    #[test]
    fn the_retired_amqp_broker_variables_are_neither_required_nor_read() {
        let vars = valid_vars();

        let config = Config::from_source(|key| {
            assert!(
                !key.starts_with("MS_NMAP_BROKER_"),
                "la config no debe consultar variables del Broker AMQP retirado: {key}"
            );
            vars.get(key).map(|v| (*v).to_owned())
        })
        .expect("sin MS_NMAP_BROKER_* la config debe cargar");

        assert_eq!(config.aws_region, "us-east-1");
    }

    #[test]
    fn missing_mongo_db_var_yields_typed_missing_var_error() {
        let mut vars = valid_vars();
        vars.remove(MONGO_DB_VAR);

        let err = config_from(&vars).expect_err("sin MONGO_DB debe fallar");

        assert!(matches!(err, ConfigError::MissingVar(MONGO_DB_VAR)));
    }

    #[test]
    fn missing_ssh_port_var_yields_typed_missing_var_error() {
        let mut vars = valid_vars();
        vars.remove(SSH_PORT_VAR);

        let err = config_from(&vars).expect_err("sin SSH_PORT debe fallar");

        assert!(matches!(err, ConfigError::MissingVar(SSH_PORT_VAR)));
    }

    #[test]
    fn non_numeric_ssh_port_yields_typed_invalid_value_error() {
        let mut vars = valid_vars();
        vars.insert(SSH_PORT_VAR, "ssh");

        let err = config_from(&vars).expect_err("puerto no numérico debe fallar");

        match err {
            ConfigError::InvalidValue { var, .. } => assert_eq!(var, SSH_PORT_VAR),
            other => panic!("se esperaba InvalidValue, se obtuvo {other:?}"),
        }
    }

    #[test]
    fn out_of_range_ssh_port_yields_typed_invalid_value_error() {
        for bad in ["0", "70000"] {
            let mut vars = valid_vars();
            vars.insert(SSH_PORT_VAR, bad);

            let err = config_from(&vars).expect_err("puerto fuera de rango debe fallar");

            match err {
                ConfigError::InvalidValue { var, .. } => assert_eq!(var, SSH_PORT_VAR),
                other => panic!("se esperaba InvalidValue para {bad:?}, se obtuvo {other:?}"),
            }
        }
    }

    #[test]
    fn missing_ssh_connect_timeout_var_yields_typed_missing_var_error() {
        let mut vars = valid_vars();
        vars.remove(SSH_CONNECT_TIMEOUT_VAR);

        let err = config_from(&vars).expect_err("sin timeout de conexión SSH debe fallar");

        assert!(matches!(
            err,
            ConfigError::MissingVar(SSH_CONNECT_TIMEOUT_VAR)
        ));
    }

    #[test]
    fn missing_ssh_command_timeout_var_yields_typed_missing_var_error() {
        let mut vars = valid_vars();
        vars.remove(SSH_COMMAND_TIMEOUT_VAR);

        let err = config_from(&vars).expect_err("sin timeout de comando SSH debe fallar");

        assert!(matches!(
            err,
            ConfigError::MissingVar(SSH_COMMAND_TIMEOUT_VAR)
        ));
    }

    #[test]
    fn non_numeric_timeout_yields_typed_invalid_value_error() {
        let mut vars = valid_vars();
        vars.insert(SSH_CONNECT_TIMEOUT_VAR, "diez");

        let err = config_from(&vars).expect_err("timeout no numérico debe fallar");

        match err {
            ConfigError::InvalidValue { var, .. } => assert_eq!(var, SSH_CONNECT_TIMEOUT_VAR),
            other => panic!("se esperaba InvalidValue, se obtuvo {other:?}"),
        }
    }

    #[test]
    fn zero_timeout_yields_typed_invalid_value_error() {
        let mut vars = valid_vars();
        vars.insert(SSH_COMMAND_TIMEOUT_VAR, "0");

        let err = config_from(&vars).expect_err("timeout cero debe fallar");

        match err {
            ConfigError::InvalidValue { var, .. } => assert_eq!(var, SSH_COMMAND_TIMEOUT_VAR),
            other => panic!("se esperaba InvalidValue, se obtuvo {other:?}"),
        }
    }

    #[test]
    fn debug_output_does_not_leak_nvd_api_key() {
        let mut vars = valid_vars();
        vars.insert(NVD_API_KEY_VAR, "nvd-super-secret-key");

        let config = config_from(&vars).expect("config válida");
        let rendered = format!("{config:?}");

        assert!(
            !rendered.contains("nvd-super-secret-key"),
            "Debug de Config no debe exponer la API key de NVD: {rendered}"
        );
    }

    #[test]
    fn loads_aws_messaging_settings() {
        let config = config_from(&valid_vars()).expect("la config válida debe cargar");

        assert_eq!(config.aws_region, "us-east-1");
        assert!(config.aws_endpoint_url.is_none());
        assert_eq!(
            config.scan_requests_queue_url.as_str(),
            VALID_REQUESTS_QUEUE_URL
        );
        assert_eq!(
            config.scan_cancellations_queue_url.as_str(),
            VALID_CANCELLATIONS_QUEUE_URL
        );
        assert_eq!(
            config.scan_requests_dlq_url.as_str(),
            VALID_REQUESTS_DLQ_URL
        );
        assert_eq!(
            config.scan_cancellations_dlq_url.as_str(),
            VALID_CANCELLATIONS_DLQ_URL
        );
        assert_eq!(config.scan_outcomes_topic_arn, VALID_OUTCOMES_TOPIC_ARN);
    }

    #[test]
    fn each_missing_aws_messaging_var_yields_missing_var_error() {
        for name in NEW_REQUIRED_VARS {
            let mut vars = valid_vars();
            vars.remove(name);

            let err = config_from(&vars).expect_err("falta una variable requerida");

            assert!(
                matches!(err, ConfigError::MissingVar(n) if n == name),
                "esperaba MissingVar({name}), obtuve {err:?}"
            );
        }
    }

    #[test]
    fn empty_aws_messaging_var_is_treated_as_missing() {
        for name in NEW_REQUIRED_VARS {
            let mut vars = valid_vars();
            vars.insert(name, "  ");

            let err = config_from(&vars).expect_err("valor vacío debe fallar");

            assert!(
                matches!(err, ConfigError::MissingVar(n) if n == name),
                "esperaba MissingVar({name}), obtuve {err:?}"
            );
        }
    }

    #[test]
    fn aws_endpoint_url_is_optional() {
        let mut vars = valid_vars();
        vars.insert(AWS_ENDPOINT_URL_VAR, "  ");

        let config = config_from(&vars).expect("endpoint vacío equivale a ausente");

        assert!(config.aws_endpoint_url.is_none());
    }

    #[test]
    fn valid_aws_endpoint_url_is_parsed() {
        let mut vars = valid_vars();
        vars.insert(AWS_ENDPOINT_URL_VAR, "http://localstack:4566");

        let config = config_from(&vars).expect("endpoint válido debe cargar");

        assert_eq!(
            config.aws_endpoint_url.expect("debe ser Some").as_str(),
            "http://localstack:4566/"
        );
    }

    #[test]
    fn invalid_urls_yield_typed_invalid_url_error() {
        for name in [
            AWS_ENDPOINT_URL_VAR,
            SCAN_REQUESTS_QUEUE_URL_VAR,
            SCAN_CANCELLATIONS_QUEUE_URL_VAR,
            SCAN_REQUESTS_DLQ_URL_VAR,
            SCAN_CANCELLATIONS_DLQ_URL_VAR,
        ] {
            for bad in ["not-a-url", "://missing-scheme", "http://"] {
                let mut vars = valid_vars();
                vars.insert(name, bad);

                let err = config_from(&vars).expect_err("URL malformada debe fallar");

                assert!(
                    matches!(err, ConfigError::InvalidUrl { var, .. } if var == name),
                    "esperaba InvalidUrl({name}) para {bad:?}, obtuve {err:?}"
                );
            }
        }
    }

    #[test]
    fn malformed_topic_arns_yield_invalid_arn_without_echoing_value() {
        for bad in [
            "not-an-arn",
            "arn:aws:sqs:us-east-1:123456789012:scan-outcomes",
            "arn:aws:sns:us-east-1:123456789012",
            "arn:aws:sns:us-east-1:12345:scan-outcomes",
            "arn:aws:sns:us-east-1:12345678901a:scan-outcomes",
            "arn:aws:sns:us-east-1:123456789012:",
            "arn:aws:sns::123456789012:scan-outcomes",
            "arn::sns:us-east-1:123456789012:scan-outcomes",
            "arn:aws:sns:us-east-1:123456789012:scan:outcomes",
        ] {
            let mut vars = valid_vars();
            vars.insert(SCAN_OUTCOMES_TOPIC_ARN_VAR, bad);

            let err = config_from(&vars).expect_err("ARN malformado debe fallar");

            assert!(
                matches!(err, ConfigError::InvalidArn { var } if var == SCAN_OUTCOMES_TOPIC_ARN_VAR),
                "esperaba InvalidArn para {bad:?}, obtuve {err:?}"
            );
            assert!(
                !err.to_string().contains(bad),
                "el mensaje no debe repetir el valor: {err}"
            );
        }
    }

    #[test]
    fn debug_output_still_redacts_secrets_with_aws_settings() {
        let mut vars = valid_vars();
        vars.insert(NVD_API_KEY_VAR, "nvd-super-secret-key");

        let config = config_from(&vars).expect("config válida");
        let rendered = format!("{config:?}");

        assert!(!rendered.contains("nvd-super-secret-key"));
    }
}
