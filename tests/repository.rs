//! Tests de integración de `nmap_service::repository` contra un contenedor real
//! de MongoDB (`mongo:7`) levantado con `testcontainers`.
//!
//! Todos requieren Docker y están marcados `#[ignore = "requiere Docker"]`:
//! `cargo test` los omite; `cargo test -- --ignored` los ejecuta. Nunca se
//! ejecutan contra `db-nmap` de producción: siempre contra el contenedor
//! desechable (base `db-nmap-test`).

use std::time::Duration;

use mongodb::bson::{doc, oid::ObjectId, Document};
use mongodb::IndexModel;
use testcontainers::{
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
    ContainerAsync, GenericImage, ImageExt,
};
use time::format_description::well_known::Rfc3339;
use time::macros::datetime;
use time::OffsetDateTime;

use nmap_service::domain::{
    CorrelationId, PortFinding, PortState, Protocol, ScanResult, Severity, VulnFinding, VulnSource,
};
use nmap_service::enrichment::NvdCache;
use nmap_service::repository::{MongoRepository, ScanId};
use nmap_service::ssh::{Fingerprint, HostKeyStore};

const MONGO_IMAGE: &str = "mongo";
const MONGO_TAG: &str = "7";
const MONGO_PORT: u16 = 27017;
const TEST_DB: &str = "db-nmap-test";

async fn start_mongo() -> ContainerAsync<GenericImage> {
    GenericImage::new(MONGO_IMAGE, MONGO_TAG)
        .with_exposed_port(MONGO_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Waiting for connections"))
        .with_startup_timeout(Duration::from_secs(180))
        .start()
        .await
        .expect("el contenedor mongo debe arrancar")
}

async fn uri(container: &ContainerAsync<GenericImage>) -> String {
    let host = container
        .get_host()
        .await
        .expect("host del contenedor")
        .to_string();
    let port = container
        .get_host_port_ipv4(MONGO_PORT)
        .await
        .expect("puerto mapeado");
    format!("mongodb://{host}:{port}/?directConnection=true&serverSelectionTimeoutMS=5000")
}

async fn connect(container: &ContainerAsync<GenericImage>) -> MongoRepository {
    MongoRepository::connect(&uri(container).await, TEST_DB)
        .await
        .expect("debe conectar con el contenedor mongo")
}

fn sample_result() -> ScanResult {
    ScanResult {
        host: "192.0.2.10".parse().expect("IP de prueba válida"),
        ports: vec![
            PortFinding {
                port: 22,
                protocol: Protocol::Tcp,
                state: PortState::Open,
                service: Some("ssh".to_owned()),
                version: Some("OpenSSH 9.6p1".to_owned()),
                cpes: vec!["cpe:/a:openbsd:openssh:9.6p1".to_owned()],
            },
            PortFinding {
                port: 443,
                protocol: Protocol::Tcp,
                state: PortState::Filtered,
                service: Some("https".to_owned()),
                version: None,
                cpes: Vec::new(),
            },
        ],
        vulnerabilities: vec![VulnFinding {
            id: Some("CVE-2023-38408".to_owned()),
            severity: Severity::High,
            description: "ssh-agent PKCS#11 arbitrary code execution".to_owned(),
            nse_script: "ssh-vuln-cve2023-38408".to_owned(),
            source: VulnSource::NmapNse,
            references: vec!["https://www.openssh.com/txt/release-9.3p2".to_owned()],
        }],
        scanned_at: datetime!(2026-08-27 12:30:00 UTC),
    }
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn save_then_find_by_id_returns_the_same_scan_result() {
    let container = start_mongo().await;
    let repo = connect(&container).await;
    let expected = sample_result();
    let correlation_id = CorrelationId::new("corr-find-by-id");

    let id = repo
        .save(&expected, &correlation_id)
        .await
        .expect("save debe devolver un ScanId");

    let found = repo
        .find_by_id(&id)
        .await
        .expect("find_by_id no debe fallar")
        .expect("el ScanResult recién guardado debe existir");

    assert_eq!(found, expected);
    assert_eq!(found.ports.len(), 2);
    assert_eq!(found.ports[1].port, 443);
    assert_eq!(found.ports[1].state, PortState::Filtered);
    assert_eq!(
        found.vulnerabilities[0].id.as_deref(),
        Some("CVE-2023-38408")
    );
    assert_eq!(found.vulnerabilities[0].severity, Severity::High);
    assert_eq!(found.scanned_at, datetime!(2026-08-27 12:30:00 UTC));
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn save_then_find_by_correlation_id_returns_the_scan_result() {
    let container = start_mongo().await;
    let repo = connect(&container).await;
    let expected = sample_result();
    let correlation_id = CorrelationId::new("corr-42-abc");

    repo.save(&expected, &correlation_id)
        .await
        .expect("save debe funcionar");

    let found = repo
        .find_by_correlation_id(&correlation_id)
        .await
        .expect("find_by_correlation_id no debe fallar")
        .expect("debe encontrar el ScanResult por correlation_id");

    assert_eq!(found, expected);

    let missing = repo
        .find_by_correlation_id(&CorrelationId::new("corr-inexistente"))
        .await
        .expect("no debe fallar");
    assert!(
        missing.is_none(),
        "un correlation_id desconocido devuelve None"
    );
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn find_by_id_of_unknown_id_returns_none() {
    let container = start_mongo().await;
    let repo = connect(&container).await;

    let unknown = ScanId::from(ObjectId::new());
    let found = repo
        .find_by_id(&unknown)
        .await
        .expect("un id inexistente NO es un error");

    assert!(found.is_none(), "un id inexistente devuelve Ok(None)");
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn stored_document_carries_timestamp_and_correlation_id() {
    let container = start_mongo().await;
    let repo = connect(&container).await;
    let correlation_id = CorrelationId::new("corr-doc-shape");

    let before = OffsetDateTime::now_utc();
    let id = repo
        .save(&sample_result(), &correlation_id)
        .await
        .expect("save debe funcionar");
    let after = OffsetDateTime::now_utc();

    let client = mongodb::Client::with_uri_str(&uri(&container).await)
        .await
        .expect("cliente raw");
    let raw: mongodb::Collection<Document> = client.database(TEST_DB).collection("scan_results");
    let document = raw
        .find_one(doc! { "_id": ObjectId::parse_str(id.as_str()).expect("id hex") })
        .await
        .expect("consulta raw")
        .expect("el documento existe");

    assert_eq!(
        document
            .get_str("correlation_id")
            .expect("correlation_id de texto"),
        "corr-doc-shape"
    );

    let timestamp = document.get_str("timestamp").expect("timestamp de texto");
    let parsed = OffsetDateTime::parse(timestamp, &Rfc3339).expect("timestamp es RFC 3339");
    assert!(
        parsed >= before - Duration::from_secs(2) && parsed <= after + Duration::from_secs(2),
        "el timestamp de guardado {parsed} está fuera del rango [{before}, {after}]"
    );

    assert!(
        document.get_document("result").is_ok(),
        "el ScanResult se guarda bajo la clave `result`"
    );
    let scanned_at = document
        .get_document("result")
        .expect("subdocumento result")
        .get_str("scanned_at")
        .expect("scanned_at de texto");
    assert!(
        scanned_at.starts_with("2026-08-27T12:30:00"),
        "scanned_at se persiste como string RFC 3339: {scanned_at}"
    );
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn mongo_host_key_store_remembers_and_recalls_a_fingerprint() {
    let container = start_mongo().await;
    let store = connect(&container).await.host_key_store();

    assert!(
        store
            .known_fingerprint("192.0.2.50")
            .await
            .expect("consulta al almacén")
            .is_none(),
        "un host desconocido devuelve Ok(None)"
    );

    let fingerprint = Fingerprint::from_sha256_bytes([0xAB; 32]);
    store
        .remember("192.0.2.50", fingerprint.clone())
        .await
        .expect("remember no debe fallar");

    assert_eq!(
        store
            .known_fingerprint("192.0.2.50")
            .await
            .expect("consulta al almacén"),
        Some(fingerprint)
    );
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn mongo_host_key_store_persists_across_new_instances() {
    let container = start_mongo().await;
    let fingerprint = Fingerprint::from_sha256_bytes([7u8; 32]);

    {
        let store = connect(&container).await.host_key_store();
        store
            .remember("10.0.0.9", fingerprint.clone())
            .await
            .expect("remember no debe fallar");
    }

    // Nueva conexión (nuevo Client) sobre la misma colección: simula un
    // reinicio o una réplica distinta del servicio.
    let reopened = connect(&container).await.host_key_store();
    assert_eq!(
        reopened
            .known_fingerprint("10.0.0.9")
            .await
            .expect("consulta al almacén"),
        Some(fingerprint),
        "el fingerprint debe seguir visible tras reabrir el almacén"
    );

    // `remember` es idempotente: no rompe ni cambia el fingerprint registrado.
    reopened
        .remember("10.0.0.9", Fingerprint::from_sha256_bytes([7u8; 32]))
        .await
        .expect("remember idempotente");
    assert_eq!(
        reopened
            .known_fingerprint("10.0.0.9")
            .await
            .expect("consulta al almacén"),
        Some(Fingerprint::from_sha256_bytes([7u8; 32]))
    );
}

fn sample_nvd_findings() -> Vec<VulnFinding> {
    vec![VulnFinding {
        id: Some("CVE-2024-9999".to_owned()),
        severity: Severity::High,
        description: "hallazgo de prueba de la caché NVD".to_owned(),
        nse_script: String::new(),
        source: VulnSource::Nvd,
        references: vec!["https://example.test/advisory".to_owned()],
    }]
}

/// Devuelve `(keys, expire_after_seconds)` del índice cuyo `keys` sea
/// exactamente `{"cached_at": 1}` en la colección `nvd_cache`, o `None` si no
/// existe. Se consulta con un cliente "crudo" (no vía `MongoNvdCache`) para
/// verificar la forma real del índice en el servidor.
async fn nvd_cache_ttl_index_expire_after_seconds(
    container: &ContainerAsync<GenericImage>,
) -> Option<Duration> {
    let client = mongodb::Client::with_uri_str(&uri(container).await)
        .await
        .expect("cliente raw");
    let raw: mongodb::Collection<Document> = client.database(TEST_DB).collection("nvd_cache");

    let mut cursor = raw.list_indexes().await.expect("listIndexes");
    let mut found = None;
    while cursor
        .advance()
        .await
        .expect("avanzar el cursor de índices")
    {
        let index: IndexModel = cursor
            .deserialize_current()
            .expect("el índice se deserializa como IndexModel");
        if index.keys == doc! { "cached_at": 1 } {
            found = index.options.and_then(|options| options.expire_after);
        }
    }
    found
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn nvd_cache_put_then_get_returns_the_same_findings() {
    let container = start_mongo().await;
    let repo = connect(&container).await;
    let cache = repo
        .nvd_cache_store(Duration::from_secs(3600))
        .await
        .expect("nvd_cache_store debe crear el índice TTL y devolver la caché");

    let cpe = "cpe:2.3:a:openbsd:openssh:9.9:*:*:*:*:*:*:*";
    assert!(
        cache
            .get(cpe)
            .await
            .expect("consulta a la caché no debe fallar")
            .is_none(),
        "un CPE nunca cacheado debe ser un miss"
    );

    let findings = sample_nvd_findings();
    cache.put(cpe, &findings).await.expect("put no debe fallar");

    let cached = cache
        .get(cpe)
        .await
        .expect("consulta a la caché no debe fallar")
        .expect("debe haber un hit justo después del put");
    assert_eq!(cached, findings);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn nvd_cache_get_of_unknown_cpe_is_a_miss_not_an_error() {
    let container = start_mongo().await;
    let repo = connect(&container).await;
    let cache = repo
        .nvd_cache_store(Duration::from_secs(3600))
        .await
        .expect("nvd_cache_store no debe fallar");

    let result = cache
        .get("cpe:2.3:a:nadie:nada:0.0:*:*:*:*:*:*:*")
        .await
        .expect("un miss no es un error");
    assert!(result.is_none());
}

/// El índice TTL de MongoDB expira documentos con un job de fondo que corre
/// cada ~60s por defecto: esperar el borrado real dentro de un test haría el
/// test lento y flaky. En su lugar, se verifica directamente contra el
/// servidor que el índice `expireAfterSeconds` sobre `cached_at` se creó con
/// el valor de `ttl` pasado a `nvd_cache_store` (documentado en
/// `progress/impl_nvd_enrichment.md`).
#[tokio::test]
#[ignore = "requiere Docker"]
async fn nvd_cache_store_creates_a_ttl_index_with_the_configured_expire_after_seconds() {
    let container = start_mongo().await;
    let repo = connect(&container).await;

    repo.nvd_cache_store(Duration::from_secs(3600))
        .await
        .expect("nvd_cache_store debe crear el índice TTL");

    let expire_after = nvd_cache_ttl_index_expire_after_seconds(&container).await;
    assert_eq!(expire_after, Some(Duration::from_secs(3600)));
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn nvd_cache_store_is_idempotent_when_called_twice_with_the_same_ttl() {
    let container = start_mongo().await;
    let repo = connect(&container).await;

    repo.nvd_cache_store(Duration::from_secs(1800))
        .await
        .expect("primera llamada debe crear el índice");
    repo.nvd_cache_store(Duration::from_secs(1800))
        .await
        .expect("segunda llamada con el mismo TTL debe ser idempotente, no un error");

    let expire_after = nvd_cache_ttl_index_expire_after_seconds(&container).await;
    assert_eq!(expire_after, Some(Duration::from_secs(1800)));
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn nvd_cache_store_updates_the_ttl_via_collmod_when_the_ttl_changes() {
    let container = start_mongo().await;
    let repo = connect(&container).await;

    repo.nvd_cache_store(Duration::from_secs(60))
        .await
        .expect("primer TTL debe crear el índice");
    // MongoDB rechaza `createIndexes` para un índice ya existente con otro
    // `expireAfterSeconds` (ver `ensure_nvd_cache_ttl_index` en
    // `src/repository.rs`); esta llamada debe recurrir a `collMod` y no fallar.
    repo.nvd_cache_store(Duration::from_secs(120))
        .await
        .expect("cambiar el TTL debe actualizar el índice vía collMod, no fallar");

    let expire_after = nvd_cache_ttl_index_expire_after_seconds(&container).await;
    assert_eq!(expire_after, Some(Duration::from_secs(120)));
}
