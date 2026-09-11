//! Enriquecimiento de vulnerabilidades: una etapa del pipeline situada entre
//! `parser` y `repository` que cruza los servicios+versiones descubiertos por
//! `nmap -sV` contra bases de vulnerabilidades/exploits conocidos y añade
//! [`VulnFinding`]s al [`crate::domain::ScanResult`].
//!
//! El puerto hexagonal es [`VulnEnricher`]. Hay dos adaptadores:
//!
//! - [`ExploitDbEnricher`] (submódulo [`exploitdb`]): **offline**, un lookup en
//!   memoria sobre el CSV `files_exploits.csv` de Exploit-DB, **sin egress de
//!   red** (ver `docs/security-scope.md`: es detección pasiva, misma categoría
//!   que `--script vuln`).
//! - [`NvdApiEnricher`] (submódulo [`nvd`]): consulta la API NVD 2.0 por CPE.
//!   **Sí hace egress de red**, pero sólo si se habilita explícitamente (ver
//!   `docs/security-scope.md` y [`crate::config`]). Sólo envía el CPE del
//!   servicio, nunca la IP del objetivo, el `correlation_id` ni credenciales.
//!
//! Ambos se combinan con [`CompositeVulnEnricher`], que es además el punto de
//! extensión para futuros adaptadores (Vulners, ...) sin tocar el pipeline.

use std::sync::Arc;

use async_trait::async_trait;

use crate::domain::PortFinding;
use crate::domain::VulnFinding;

pub mod exploitdb;
pub mod nvd;

pub use exploitdb::ExploitDbEnricher;
pub use nvd::{InMemoryNvdCache, NvdApiEnricher, NvdCache};

/// Error de un [`VulnEnricher`].
#[derive(Debug, thiserror::Error)]
pub enum EnrichError {
    /// No se pudo leer o parsear la fuente de datos local (p. ej. el CSV de
    /// Exploit-DB no existe o no tiene las columnas esperadas).
    #[error("fuente de datos de enriquecimiento inaccesible: {0}")]
    DataSource(String),
    /// Un backend remoto de enriquecimiento (p. ej. la API NVD) falló: error de
    /// red, respuesta HTTP no exitosa, o cuerpo no parseable. También cubre
    /// fallos del backend de caché ([`NvdCache`]) cuando su implementación real
    /// (Mongo) no está disponible.
    #[error("backend de enriquecimiento falló: {0}")]
    Backend(String),
}

/// Puerto hexagonal: dado el conjunto de [`PortFinding`]s descubiertos, devuelve
/// [`VulnFinding`]s adicionales cruzándolos contra una base de vulnerabilidades.
///
/// El pipeline lo invoca en modo *best-effort*: un [`Err`] no aborta el escaneo
/// (ver [`crate::pipeline`]).
#[async_trait]
pub trait VulnEnricher: Send + Sync {
    /// Devuelve los hallazgos adicionales para `ports`. No modifica `ports` ni
    /// hace suposiciones sobre el orden.
    ///
    /// # Errores
    ///
    /// [`EnrichError`] si la fuente de datos subyacente no está disponible.
    async fn enrich(&self, ports: &[PortFinding]) -> Result<Vec<VulnFinding>, EnrichError>;
}

/// Combina varios [`VulnEnricher`]: ejecuta **todos** y concatena sus hallazgos.
///
/// Es el punto de extensión para futuros adaptadores (Vulners, ...). Si uno
/// devuelve [`Err`], se registra con `tracing::warn!` y se continúa con los
/// demás: el enriquecimiento es best-effort y la ausencia de una fuente no debe
/// tumbar a las otras. La deduplicación de los hallazgos (contra los de `nmap` y
/// entre sí) la hace el pipeline, no este composite.
pub struct CompositeVulnEnricher {
    enrichers: Vec<Arc<dyn VulnEnricher>>,
}

impl CompositeVulnEnricher {
    /// Crea el composite a partir de los enrichers dados (se ejecutan en orden).
    pub fn new(enrichers: Vec<Arc<dyn VulnEnricher>>) -> Self {
        Self { enrichers }
    }
}

#[async_trait]
impl VulnEnricher for CompositeVulnEnricher {
    async fn enrich(&self, ports: &[PortFinding]) -> Result<Vec<VulnFinding>, EnrichError> {
        let mut all = Vec::new();
        for enricher in &self.enrichers {
            match enricher.enrich(ports).await {
                Ok(mut found) => all.append(&mut found),
                Err(err) => tracing::warn!(
                    error = %err,
                    "un enricher falló; se continúa con los demás"
                ),
            }
        }
        Ok(all)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Severity, VulnSource};

    struct StubEnricher(Vec<VulnFinding>);

    #[async_trait]
    impl VulnEnricher for StubEnricher {
        async fn enrich(&self, _ports: &[PortFinding]) -> Result<Vec<VulnFinding>, EnrichError> {
            Ok(self.0.clone())
        }
    }

    struct FailingEnricher;

    #[async_trait]
    impl VulnEnricher for FailingEnricher {
        async fn enrich(&self, _ports: &[PortFinding]) -> Result<Vec<VulnFinding>, EnrichError> {
            Err(EnrichError::Backend("caído".to_owned()))
        }
    }

    fn dummy_finding(id: &str) -> VulnFinding {
        VulnFinding {
            id: Some(id.to_owned()),
            severity: Severity::Unknown,
            description: id.to_owned(),
            nse_script: String::new(),
            source: VulnSource::ExploitDb,
            references: Vec::new(),
        }
    }

    #[tokio::test]
    async fn composite_concatenates_every_enricher() {
        let composite = CompositeVulnEnricher::new(vec![
            Arc::new(StubEnricher(vec![dummy_finding("CVE-1")])) as Arc<dyn VulnEnricher>,
            Arc::new(StubEnricher(vec![
                dummy_finding("CVE-2"),
                dummy_finding("CVE-3"),
            ])),
        ]);

        let out = composite.enrich(&[]).await.unwrap();

        assert_eq!(out.len(), 3);
    }

    #[tokio::test]
    async fn composite_keeps_going_when_one_enricher_errors() {
        let composite = CompositeVulnEnricher::new(vec![
            Arc::new(FailingEnricher) as Arc<dyn VulnEnricher>,
            Arc::new(StubEnricher(vec![dummy_finding("CVE-9")])),
        ]);

        let out = composite
            .enrich(&[])
            .await
            .expect("el composite no propaga el error de un enricher");

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id.as_deref(), Some("CVE-9"));
    }
}
