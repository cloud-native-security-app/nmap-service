//! Carga y validación de la configuración del servicio desde variables de
//! entorno (URI de MongoDB, endpoint/credenciales del Broker, timeouts SSH).
//!
//! La lectura del entorno del proceso ([`Config::from_env`]) se separa de la
//! lógica de validación (`Config::from_source`, privada) para poder testear
//! esta última con un mapa inyectado, sin mutar variables de entorno globales
//! del proceso ni depender del orden de ejecución de los tests.

use std::time::Duration;

use secrecy::SecretString;

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

/// Nombre de la variable de entorno con el endpoint del Broker.
pub const BROKER_ENDPOINT_VAR: &str = "MS_NMAP_BROKER_ENDPOINT";

/// Nombre de la variable de entorno con la credencial (token/password) de
/// acceso al Broker. Su valor se trata como secreto (ver `docs/security-scope.md`).
pub const BROKER_CREDENTIAL_VAR: &str = "MS_NMAP_BROKER_CREDENTIAL";

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
}

/// Configuración validada del servicio `ms-nmap`.
///
/// Se construye una sola vez al arrancar con [`Config::from_env`]. Todos sus
/// valores provienen del entorno; el código no hardcodea URIs, endpoints ni
/// timeouts de negocio.
///
/// El campo [`Config::broker_credential`] es un [`SecretString`]: su contenido
/// se redacta al formatear la struct con `Debug`, de modo que no puede
/// filtrarse por accidente vía `tracing::debug!`/`error!` ni en un panic.
#[derive(Debug)]
pub struct Config {
    /// URI de conexión a MongoDB (`db-nmap`).
    pub mongo_uri: String,
    /// Nombre de la base de datos de MongoDB que usa el servicio.
    pub mongo_db: String,
    /// Puerto SSH del objetivo (`1..=65535`).
    pub ssh_port: u16,
    /// Endpoint del Broker (cola de mensajes) al que se conecta el servicio.
    pub broker_endpoint: String,
    /// Credencial de acceso al Broker. Contenido redactado en `Debug`.
    pub broker_credential: SecretString,
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
}

impl Config {
    /// Construye la configuración leyendo las variables de entorno del proceso.
    ///
    /// # Errores
    ///
    /// - [`ConfigError::MissingVar`] si falta (o está vacía) una variable
    ///   requerida: [`MONGO_URI_VAR`], [`MONGO_DB_VAR`], [`SSH_PORT_VAR`],
    ///   [`BROKER_ENDPOINT_VAR`], [`BROKER_CREDENTIAL_VAR`],
    ///   [`SSH_CONNECT_TIMEOUT_VAR`], [`SSH_COMMAND_TIMEOUT_VAR`],
    ///   [`EXPLOITDB_CSV_VAR`], [`NVD_ENRICHMENT_ENABLED_VAR`], o
    ///   [`NVD_CACHE_TTL_VAR`] cuando [`NVD_ENRICHMENT_ENABLED_VAR`] es
    ///   `"true"`.
    /// - [`ConfigError::InvalidValue`] si un timeout está presente pero no es
    ///   un entero de segundos positivo, si [`SSH_PORT_VAR`] no es un entero en
    ///   el rango `1..=65535`, o si [`NVD_ENRICHMENT_ENABLED_VAR`] no es
    ///   exactamente `"true"` o `"false"`.
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
        let broker_endpoint = required(BROKER_ENDPOINT_VAR, lookup(BROKER_ENDPOINT_VAR))?;
        let broker_credential = required(BROKER_CREDENTIAL_VAR, lookup(BROKER_CREDENTIAL_VAR))?;

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

        Ok(Self {
            mongo_uri,
            mongo_db,
            ssh_port,
            broker_endpoint,
            broker_credential: SecretString::from(broker_credential),
            ssh_connect_timeout,
            ssh_command_timeout,
            exploitdb_csv,
            nvd_enrichment_enabled,
            nvd_api_key,
            nvd_cache_ttl,
        })
    }
}

fn required(var: &'static str, raw: Option<String>) -> Result<String, ConfigError> {
    match raw {
        Some(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(ConfigError::MissingVar(var)),
    }
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use secrecy::ExposeSecret;

    use super::*;

    const TEST_BROKER_CREDENTIAL: &str = "s3cr3t-token";

    fn valid_vars() -> HashMap<&'static str, &'static str> {
        HashMap::from([
            (MONGO_URI_VAR, "mongodb://db-nmap:27017/nmap"),
            (MONGO_DB_VAR, "db-nmap"),
            (SSH_PORT_VAR, "22"),
            (BROKER_ENDPOINT_VAR, "amqp://broker:5672"),
            (BROKER_CREDENTIAL_VAR, TEST_BROKER_CREDENTIAL),
            (SSH_CONNECT_TIMEOUT_VAR, "7"),
            (SSH_COMMAND_TIMEOUT_VAR, "120"),
            (EXPLOITDB_CSV_VAR, "/opt/exploitdb/files_exploits.csv"),
            (NVD_ENRICHMENT_ENABLED_VAR, "false"),
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
        assert_eq!(config.broker_endpoint, "amqp://broker:5672");
        assert_eq!(
            config.broker_credential.expose_secret(),
            TEST_BROKER_CREDENTIAL
        );
        assert_eq!(config.ssh_connect_timeout, Duration::from_secs(7));
        assert_eq!(config.ssh_command_timeout, Duration::from_secs(120));
        assert_eq!(config.exploitdb_csv, "/opt/exploitdb/files_exploits.csv");
        assert!(!config.nvd_enrichment_enabled);
        assert!(config.nvd_api_key.is_none());
        assert!(config.nvd_cache_ttl.is_none());
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
        vars.insert(BROKER_CREDENTIAL_VAR, "   ");

        let err = config_from(&vars).expect_err("credencial vacía debe fallar");

        assert!(matches!(
            err,
            ConfigError::MissingVar(BROKER_CREDENTIAL_VAR)
        ));
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
    fn debug_output_does_not_leak_broker_credential() {
        let config = config_from(&valid_vars()).expect("la config válida debe cargar");

        let rendered = format!("{config:?}");

        assert!(
            !rendered.contains("s3cr3t-token"),
            "Debug de Config no debe exponer la credencial: {rendered}"
        );
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
}
