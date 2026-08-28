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
}

impl Config {
    /// Construye la configuración leyendo las variables de entorno del proceso.
    ///
    /// # Errores
    ///
    /// - [`ConfigError::MissingVar`] si falta (o está vacía) una variable
    ///   requerida: [`MONGO_URI_VAR`], [`MONGO_DB_VAR`], [`SSH_PORT_VAR`],
    ///   [`BROKER_ENDPOINT_VAR`], [`BROKER_CREDENTIAL_VAR`],
    ///   [`SSH_CONNECT_TIMEOUT_VAR`] o [`SSH_COMMAND_TIMEOUT_VAR`].
    /// - [`ConfigError::InvalidValue`] si un timeout está presente pero no es
    ///   un entero de segundos positivo, o si [`SSH_PORT_VAR`] no es un entero
    ///   en el rango `1..=65535`.
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

        Ok(Self {
            mongo_uri,
            mongo_db,
            ssh_port,
            broker_endpoint,
            broker_credential: SecretString::from(broker_credential),
            ssh_connect_timeout,
            ssh_command_timeout,
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
}
