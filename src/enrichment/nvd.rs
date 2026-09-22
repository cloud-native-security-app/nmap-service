//! Adaptador **online** de [`VulnEnricher`] que consulta la API NVD 2.0
//! (`https://services.nvd.nist.gov/rest/json/cves/2.0`) por CPE.
//!
//! Sólo hace egress de red si el servicio se arranca con
//! `MS_NMAP_NVD_ENRICHMENT_ENABLED=true` (ver [`crate::config`] y
//! [`crate::wiring`]); en ese caso, el único dato que viaja hacia NVD es el CPE
//! del servicio detectado (`cpeName=cpe:2.3:...`) — nunca la IP del objetivo,
//! el `correlation_id` ni credenciales (ver `docs/security-scope.md`).

use std::collections::HashMap;
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::domain::{PortFinding, Severity, VulnFinding, VulnSource};

use super::EnrichError;
use super::VulnEnricher;

/// Endpoint de producción de la API NVD 2.0.
pub const PRODUCTION_BASE_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/// Intervalo mínimo entre llamadas cuando no hay `apiKey`: NVD documenta un
/// límite de 5 solicitudes cada 30s sin autenticar (6.0s exactos de espacio);
/// se usa un margen de 6.5s para absorber jitter.
const MIN_INTERVAL_WITHOUT_KEY: Duration = Duration::from_millis(6_500);

/// Intervalo mínimo entre llamadas cuando hay `apiKey`: NVD documenta un límite
/// de 50 solicitudes cada 30s autenticado (0.6s exactos de espacio); se usa un
/// margen de 0.7s.
const MIN_INTERVAL_WITH_KEY: Duration = Duration::from_millis(700);

/// Caché de los hallazgos de NVD por CPE 2.3.
///
/// Desacopla [`NvdApiEnricher`] de la implementación de respaldo (Mongo, ver
/// [`crate::repository::MongoNvdCache`]) para poder testear el adaptador sin
/// Docker con [`InMemoryNvdCache`].
#[async_trait]
pub trait NvdCache: Send + Sync {
    /// Devuelve los hallazgos cacheados para `cpe` (CPE 2.3), o `None` si no
    /// hay entrada (miss) o ya expiró.
    ///
    /// # Errores
    ///
    /// [`EnrichError::Backend`] si el almacén de respaldo no está disponible.
    async fn get(&self, cpe: &str) -> Result<Option<Vec<VulnFinding>>, EnrichError>;

    /// Guarda `findings` como el resultado cacheado para `cpe` (CPE 2.3).
    ///
    /// # Errores
    ///
    /// [`EnrichError::Backend`] si el almacén de respaldo no está disponible.
    async fn put(&self, cpe: &str, findings: &[VulnFinding]) -> Result<(), EnrichError>;
}

/// Implementación de [`NvdCache`] en memoria, para tests unitarios sin Docker.
///
/// No expira entradas (a diferencia de [`crate::repository::MongoNvdCache`],
/// que sí tiene TTL): es sólo un doble de test, nunca se usa en producción.
#[derive(Debug, Default)]
pub struct InMemoryNvdCache {
    entries: StdMutex<HashMap<String, Vec<VulnFinding>>>,
}

impl InMemoryNvdCache {
    /// Crea una caché en memoria vacía.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Vec<VulnFinding>>> {
        match self.entries.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

#[async_trait]
impl NvdCache for InMemoryNvdCache {
    async fn get(&self, cpe: &str) -> Result<Option<Vec<VulnFinding>>, EnrichError> {
        Ok(self.lock().get(cpe).cloned())
    }

    async fn put(&self, cpe: &str, findings: &[VulnFinding]) -> Result<(), EnrichError> {
        self.lock().insert(cpe.to_owned(), findings.to_vec());
        Ok(())
    }
}

/// Adaptador de [`VulnEnricher`] que consulta la API NVD 2.0 por CPE.
///
/// Antes de cada llamada HTTP consulta `cache`; si hay hit, no llama a la API.
/// Si hay miss, espera lo necesario para respetar `min_interval` desde la
/// última llamada (rate limiting propio, sin dependencias externas) y guarda el
/// resultado en caché tras una respuesta exitosa (best-effort: si el `put`
/// falla, se loggea y se continúa).
pub struct NvdApiEnricher {
    client: reqwest::Client,
    api_key: Option<SecretString>,
    base_url: String,
    cache: std::sync::Arc<dyn NvdCache>,
    min_interval: Duration,
    last_request: tokio::sync::Mutex<Option<Instant>>,
}

impl NvdApiEnricher {
    /// Construye el adaptador de producción, apuntando a
    /// [`PRODUCTION_BASE_URL`].
    ///
    /// `min_interval` se fija automáticamente según si `api_key` está presente
    /// (6.5s sin key, 0.7s con key; ver el módulo para la justificación de
    /// esos valores frente a los límites de tasa de NVD).
    pub fn new(api_key: Option<SecretString>, cache: std::sync::Arc<dyn NvdCache>) -> Self {
        Self::with_base_url(api_key, cache, PRODUCTION_BASE_URL.to_owned())
    }

    /// Igual que [`NvdApiEnricher::new`] pero permitiendo inyectar `base_url`:
    /// lo usan los tests para apuntar a un servidor `wiremock` local en vez de
    /// a NVD real.
    pub fn with_base_url(
        api_key: Option<SecretString>,
        cache: std::sync::Arc<dyn NvdCache>,
        base_url: String,
    ) -> Self {
        let min_interval = if api_key.is_some() {
            MIN_INTERVAL_WITH_KEY
        } else {
            MIN_INTERVAL_WITHOUT_KEY
        };
        Self {
            client: reqwest::Client::new(),
            api_key,
            base_url,
            cache,
            min_interval,
            last_request: tokio::sync::Mutex::new(None),
        }
    }

    /// Espera lo necesario para respetar `min_interval` desde la última
    /// llamada, y registra el instante de esta llamada.
    async fn wait_for_rate_limit(&self) {
        let mut last = self.last_request.lock().await;
        if let Some(previous) = *last {
            let elapsed = previous.elapsed();
            if elapsed < self.min_interval {
                tokio::time::sleep(self.min_interval - elapsed).await;
            }
        }
        *last = Some(Instant::now());
    }

    /// Devuelve los hallazgos para un único CPE 2.2 ya normalizado a CPE 2.3,
    /// resolviendo primero contra la caché y luego, en caso de miss, contra la
    /// API real.
    async fn findings_for_cpe23(&self, cpe23: &str) -> Result<Vec<VulnFinding>, EnrichError> {
        if let Some(cached) = self.cache.get(cpe23).await? {
            return Ok(cached);
        }

        self.wait_for_rate_limit().await;

        let mut request = self.client.get(&self.base_url).query(&[("cpeName", cpe23)]);
        if let Some(api_key) = &self.api_key {
            request = request.header("apiKey", api_key.expose_secret());
        }

        let response = request
            .send()
            .await
            .map_err(|err| EnrichError::Backend(format!("solicitud a NVD falló: {err}")))?;

        if !response.status().is_success() {
            return Err(EnrichError::Backend(format!(
                "NVD respondió con estado {}",
                response.status()
            )));
        }

        let body: NvdResponse = response
            .json()
            .await
            .map_err(|err| EnrichError::Backend(format!("respuesta de NVD no parseable: {err}")))?;

        let findings: Vec<VulnFinding> =
            body.vulnerabilities.iter().map(finding_from_cve).collect();

        if let Err(err) = self.cache.put(cpe23, &findings).await {
            tracing::warn!(
                error = %err,
                cpe = %cpe23,
                "no se pudo escribir en la caché de NVD; se continúa sin cachear"
            );
        }

        Ok(findings)
    }
}

#[async_trait]
impl VulnEnricher for NvdApiEnricher {
    async fn enrich(&self, ports: &[PortFinding]) -> Result<Vec<VulnFinding>, EnrichError> {
        let mut seen = std::collections::HashSet::new();
        let mut unique_cpes = Vec::new();
        for port in ports {
            for cpe in &port.cpes {
                if seen.insert(cpe.clone()) {
                    unique_cpes.push(cpe.clone());
                }
            }
        }

        let mut findings = Vec::new();
        for cpe22 in unique_cpes {
            let Some(cpe23) = cpe22_to_cpe23(&cpe22) else {
                tracing::warn!(cpe = %cpe22, "CPE con formato inesperado; se omite en NVD");
                continue;
            };
            match self.findings_for_cpe23(&cpe23).await {
                Ok(mut found) => findings.append(&mut found),
                Err(err) => tracing::warn!(
                    error = %err,
                    cpe = %cpe23,
                    "NVD: fallo consultando un CPE; se continúa con los demás"
                ),
            }
        }
        Ok(findings)
    }
}

/// Convierte un CPE 2.2 (el formato que emite `nmap`, p. ej.
/// `cpe:/a:openbsd:openssh:9.9`) al CPE 2.3 *formatted string binding* que
/// exige la API NVD 2.0 (`cpe:2.3:a:openbsd:openssh:9.9:*:*:*:*:*:*:*`).
///
/// El CPE 2.3 tiene 11 campos tras el prefijo `cpe:2.3:` (`part`, `vendor`,
/// `product`, `version`, `update`, `edition`, `language`, `sw_edition`,
/// `target_sw`, `target_hw`, `other`); el CPE 2.2 de `nmap` sólo trae los
/// primeros 4 (`part:vendor:product:version`), así que el resto se rellena con
/// `*` (comodín "no aplica"/"cualquiera").
///
/// Devuelve `None` si `cpe22` no empieza por `cpe:/` o no tiene al menos el
/// campo `part`.
fn cpe22_to_cpe23(cpe22: &str) -> Option<String> {
    const CPE23_FIELDS: usize = 11;

    let rest = cpe22.strip_prefix("cpe:/")?;
    let mut fields: Vec<&str> = rest.split(':').collect();
    if fields.is_empty() || fields[0].is_empty() {
        return None;
    }
    fields.truncate(CPE23_FIELDS);

    let mut normalized: Vec<&str> = fields
        .into_iter()
        .map(|f| if f.is_empty() { "*" } else { f })
        .collect();
    normalized.resize(CPE23_FIELDS, "*");

    Some(format!("cpe:2.3:{}", normalized.join(":")))
}

/// Cuerpo de la respuesta de `GET .../cves/2.0?cpeName=...`. Sólo se modelan
/// los campos que consume este adaptador; el resto del esquema de NVD se
/// ignora (`serde` descarta campos desconocidos por defecto).
#[derive(Debug, Deserialize)]
struct NvdResponse {
    #[serde(default)]
    vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Debug, Deserialize)]
struct NvdVulnerability {
    cve: NvdCve,
}

#[derive(Debug, Deserialize)]
struct NvdCve {
    id: String,
    #[serde(default)]
    descriptions: Vec<NvdDescription>,
    #[serde(default)]
    metrics: NvdMetrics,
    #[serde(default)]
    references: Vec<NvdReference>,
}

#[derive(Debug, Deserialize)]
struct NvdDescription {
    lang: String,
    value: String,
}

#[derive(Debug, Default, Deserialize)]
struct NvdMetrics {
    #[serde(rename = "cvssMetricV31", default)]
    cvss_v31: Vec<NvdCvssMetric>,
    #[serde(rename = "cvssMetricV30", default)]
    cvss_v30: Vec<NvdCvssMetric>,
    #[serde(rename = "cvssMetricV2", default)]
    cvss_v2: Vec<NvdCvssMetric>,
}

#[derive(Debug, Deserialize)]
struct NvdCvssMetric {
    #[serde(rename = "cvssData")]
    cvss_data: NvdCvssData,
}

#[derive(Debug, Deserialize)]
struct NvdCvssData {
    #[serde(rename = "baseScore")]
    base_score: f64,
    #[serde(rename = "baseSeverity", default)]
    base_severity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NvdReference {
    url: String,
}

fn finding_from_cve(vulnerability: &NvdVulnerability) -> VulnFinding {
    let cve = &vulnerability.cve;
    let description = cve
        .descriptions
        .iter()
        .find(|d| d.lang == "en")
        .map(|d| d.value.clone())
        .unwrap_or_default();
    let references = cve.references.iter().map(|r| r.url.clone()).collect();

    VulnFinding {
        id: Some(cve.id.clone()),
        severity: severity_from_metrics(&cve.metrics),
        description,
        nse_script: String::new(),
        source: VulnSource::Nvd,
        references,
    }
}

/// Deriva la [`Severity`] de un CVE de NVD a partir de la métrica CVSS más
/// reciente disponible (v3.1 > v3.0 > v2); [`Severity::Unknown`] si no hay
/// ninguna métrica.
///
/// | Fuente                        | Regla                                                        |
/// |--------------------------------|--------------------------------------------------------------|
/// | CVSS v3.1 / v3.0 `baseSeverity` | Mapeo 1:1: `NONE`->Info, `LOW`->Low, `MEDIUM`->Medium, `HIGH`->High, `CRITICAL`->Critical |
/// | CVSS v2 (sin `baseSeverity`)    | Umbrales NVD sobre `baseScore`: `<4.0`->Low, `4.0..=6.9`->Medium, `>=7.0`->High |
/// | Sin ninguna métrica             | [`Severity::Unknown`]                                         |
fn severity_from_metrics(metrics: &NvdMetrics) -> Severity {
    metrics
        .cvss_v31
        .first()
        .or(metrics.cvss_v30.first())
        .or(metrics.cvss_v2.first())
        .map(|metric| severity_from_cvss_data(&metric.cvss_data))
        .unwrap_or(Severity::Unknown)
}

fn severity_from_cvss_data(data: &NvdCvssData) -> Severity {
    match data.base_severity.as_deref() {
        Some(sev) => match sev.to_ascii_uppercase().as_str() {
            "NONE" => Severity::Info,
            "LOW" => Severity::Low,
            "MEDIUM" => Severity::Medium,
            "HIGH" => Severity::High,
            "CRITICAL" => Severity::Critical,
            _ => severity_from_score(data.base_score),
        },
        None => severity_from_score(data.base_score),
    }
}

/// Umbrales de severidad de CVSS v2 documentados por NVD (v2 no trae
/// `baseSeverity` en la respuesta): `<4.0` Low, `4.0..=6.9` Medium, `>=7.0`
/// High.
fn severity_from_score(base_score: f64) -> Severity {
    if base_score >= 7.0 {
        Severity::High
    } else if base_score >= 4.0 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::domain::{PortState, Protocol};

    const REAL_FIXTURE_CPE22: &str = "cpe:/a:openbsd:openssh:9.9";
    const REAL_FIXTURE_CPE23: &str = "cpe:2.3:a:openbsd:openssh:9.9:*:*:*:*:*:*:*";

    fn port_with_cpe(cpe: &str) -> PortFinding {
        PortFinding {
            port: 22,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service: Some("ssh".to_owned()),
            version: Some("9.9".to_owned()),
            cpes: vec![cpe.to_owned()],
        }
    }

    fn enricher_with_fast_interval(base_url: String, cache: Arc<dyn NvdCache>) -> NvdApiEnricher {
        let mut enricher = NvdApiEnricher::with_base_url(None, cache, base_url);
        // Los tests no deben esperar ~6.5s reales por llamada: se acelera el
        // rate limiting sólo para la instancia de test.
        enricher.min_interval = Duration::from_millis(1);
        enricher
    }

    fn nvd_body_one_cve(
        id: &str,
        base_score: f64,
        base_severity: Option<&str>,
    ) -> serde_json::Value {
        let mut cvss_data = json!({ "baseScore": base_score });
        if let Some(severity) = base_severity {
            cvss_data["baseSeverity"] = json!(severity);
        }

        json!({
            "resultsPerPage": 1,
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": id,
                        "descriptions": [
                            { "lang": "es", "value": "descripción en español" },
                            { "lang": "en", "value": format!("{id}: english description") }
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                { "source": "nvd@nist.gov", "type": "Primary", "cvssData": cvss_data }
                            ]
                        },
                        "references": [
                            { "url": "https://www.openssh.com/txt/release-9.9" }
                        ]
                    }
                }
            ]
        })
    }

    #[test]
    fn cpe22_to_cpe23_converts_the_real_fixture_cpe() {
        assert_eq!(
            cpe22_to_cpe23(REAL_FIXTURE_CPE22).as_deref(),
            Some(REAL_FIXTURE_CPE23)
        );
    }

    #[test]
    fn cpe22_to_cpe23_rejects_malformed_input() {
        assert_eq!(cpe22_to_cpe23("not-a-cpe"), None);
        assert_eq!(cpe22_to_cpe23("cpe:/"), None);
    }

    #[test]
    fn severity_prefers_v31_over_v30_and_v2() {
        let metrics = NvdMetrics {
            cvss_v31: vec![NvdCvssMetric {
                cvss_data: NvdCvssData {
                    base_score: 9.8,
                    base_severity: Some("CRITICAL".to_owned()),
                },
            }],
            cvss_v30: vec![NvdCvssMetric {
                cvss_data: NvdCvssData {
                    base_score: 1.0,
                    base_severity: Some("LOW".to_owned()),
                },
            }],
            cvss_v2: Vec::new(),
        };
        assert_eq!(severity_from_metrics(&metrics), Severity::Critical);
    }

    #[test]
    fn severity_from_v2_uses_nvd_score_thresholds_when_no_base_severity() {
        let low = NvdCvssData {
            base_score: 3.9,
            base_severity: None,
        };
        let medium = NvdCvssData {
            base_score: 6.9,
            base_severity: None,
        };
        let high = NvdCvssData {
            base_score: 7.0,
            base_severity: None,
        };
        assert_eq!(severity_from_cvss_data(&low), Severity::Low);
        assert_eq!(severity_from_cvss_data(&medium), Severity::Medium);
        assert_eq!(severity_from_cvss_data(&high), Severity::High);
    }

    #[test]
    fn severity_is_unknown_without_any_metric() {
        assert_eq!(
            severity_from_metrics(&NvdMetrics::default()),
            Severity::Unknown
        );
    }

    #[tokio::test]
    async fn enrich_maps_the_mocked_nvd_response_to_a_vuln_finding() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .and(query_param("cpeName", REAL_FIXTURE_CPE23))
            .respond_with(ResponseTemplate::new(200).set_body_json(nvd_body_one_cve(
                "CVE-2024-0001",
                9.8,
                Some("CRITICAL"),
            )))
            .expect(1)
            .mount(&server)
            .await;

        let cache: Arc<dyn NvdCache> = Arc::new(InMemoryNvdCache::new());
        let enricher = enricher_with_fast_interval(server.uri(), cache);

        let findings = enricher
            .enrich(&[port_with_cpe(REAL_FIXTURE_CPE22)])
            .await
            .expect("enrich no debe fallar");

        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.id.as_deref(), Some("CVE-2024-0001"));
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.source, VulnSource::Nvd);
        assert_eq!(finding.description, "CVE-2024-0001: english description");
        assert_eq!(
            finding.references,
            vec!["https://www.openssh.com/txt/release-9.9".to_owned()]
        );
    }

    #[tokio::test]
    async fn cache_hit_avoids_a_second_http_call() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(nvd_body_one_cve(
                "CVE-2024-0002",
                5.0,
                Some("MEDIUM"),
            )))
            .expect(1) // Sólo debe llegar UNA solicitud HTTP en todo el test.
            .mount(&server)
            .await;

        let cache: Arc<dyn NvdCache> = Arc::new(InMemoryNvdCache::new());
        let enricher = enricher_with_fast_interval(server.uri(), cache);

        let first = enricher
            .enrich(&[port_with_cpe(REAL_FIXTURE_CPE22)])
            .await
            .expect("primera llamada ok");
        let second = enricher
            .enrich(&[port_with_cpe(REAL_FIXTURE_CPE22)])
            .await
            .expect("segunda llamada ok (debe venir de caché)");

        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn duplicated_cpe_across_ports_is_queried_once() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(nvd_body_one_cve(
                "CVE-2024-0003",
                2.0,
                None,
            )))
            .expect(1)
            .mount(&server)
            .await;

        let cache: Arc<dyn NvdCache> = Arc::new(InMemoryNvdCache::new());
        let enricher = enricher_with_fast_interval(server.uri(), cache);

        let mut port_a = port_with_cpe(REAL_FIXTURE_CPE22);
        port_a.port = 22;
        let mut port_b = port_with_cpe(REAL_FIXTURE_CPE22);
        port_b.port = 2222;

        let findings = enricher
            .enrich(&[port_a, port_b])
            .await
            .expect("enrich no debe fallar");

        assert_eq!(
            findings.len(),
            1,
            "el CPE repetido sólo se consulta una vez"
        );
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[tokio::test]
    async fn http_500_yields_backend_error_without_panicking_and_keeps_other_cpes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .and(query_param("cpeName", REAL_FIXTURE_CPE23))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let other_cpe23 = "cpe:2.3:a:nginx:nginx:1.25.3:*:*:*:*:*:*:*";
        Mock::given(method("GET"))
            .and(path("/"))
            .and(query_param("cpeName", other_cpe23))
            .respond_with(ResponseTemplate::new(200).set_body_json(nvd_body_one_cve(
                "CVE-2024-0004",
                4.5,
                Some("MEDIUM"),
            )))
            .mount(&server)
            .await;

        let cache: Arc<dyn NvdCache> = Arc::new(InMemoryNvdCache::new());
        let enricher = enricher_with_fast_interval(server.uri(), cache);

        let failing_port = port_with_cpe(REAL_FIXTURE_CPE22);
        let ok_port = port_with_cpe("cpe:/a:nginx:nginx:1.25.3");

        let findings = enricher
            .enrich(&[failing_port, ok_port])
            .await
            .expect("un fallo de un CPE no debe abortar `enrich`; nunca panic");

        assert_eq!(
            findings.len(),
            1,
            "sólo el CPE que respondió 200 aporta hallazgos"
        );
        assert_eq!(findings[0].id.as_deref(), Some("CVE-2024-0004"));
    }

    #[tokio::test]
    async fn unreachable_server_yields_ok_with_no_findings_never_panics() {
        // Ningún mock montado: cualquier solicitud a este servidor falla la
        // conexión tan pronto como se apaga.
        let server = MockServer::start().await;
        let uri = server.uri();
        drop(server);

        let cache: Arc<dyn NvdCache> = Arc::new(InMemoryNvdCache::new());
        let enricher = enricher_with_fast_interval(uri, cache);

        let findings = enricher
            .enrich(&[port_with_cpe(REAL_FIXTURE_CPE22)])
            .await
            .expect("un fallo de red por CPE se loggea y no se propaga");

        assert!(findings.is_empty());
    }
}
