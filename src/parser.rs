//! Convierte el XML producido por `nmap` (`-oX`) en un [`ScanResult`] del
//! dominio. No hace IO: recibe el XML ya capturado por la capa `scanner` y es
//! testeable con fixtures reales guardadas en `tests/fixtures/`.
//!
//! El parseo usa [`roxmltree`] (árbol XML de solo lectura, Rust puro, sin
//! `unsafe` ni FFI). Se eligió frente a `quick-xml` porque el mapeo de `nmap`
//! es esencialmente navegación de un árbol pequeño (`nmaprun > host > ports >
//! port`, más los `script` anidados), y un DOM de solo lectura se lee de forma
//! mucho más directa que una máquina de estados de eventos de arranque/cierre
//! de etiqueta; el tamaño de un informe de `nmap` de una sola IP no justifica
//! el parseo en streaming.
//!
//! El parser **nunca** hace `panic!`: cualquier XML malformado, de una versión
//! de `nmap` inesperada o con valores no parseables produce un
//! [`ParseError`].
//!
//! ## Decisiones de mapeo
//!
//! - **`host`**: se toma la `<address>` con `addrtype="ipv4"` o `"ipv6"` del
//!   `<host>` (se ignora la dirección MAC).
//! - **`scanned_at`**: `<runstats><finished time="EPOCH">` (segundos Unix). Si
//!   falta, se recurre al atributo `start` de `<nmaprun>`; si tampoco está, es
//!   [`ParseError::UnexpectedStructure`].
//! - **`ports`**: cada `<port>` con su `<state>` crudo de `nmap`
//!   (`open`, `closed`, `filtered`, `unfiltered`, `open|filtered`,
//!   `closed|filtered`) mapeado a [`PortState`]. `service` = atributo `name`
//!   del `<service>`. `version` = `product` + `version` unidos por espacio, y
//!   si hay `extrainfo` se añade entre paréntesis (como lo muestra `nmap`);
//!   `None` si `nmap` no identificó nada. `cpes` = el texto de cada hijo
//!   `<cpe>` del `<service>` (`cpe:/a:openbsd:openssh:9.9`, ...); lista vacía si
//!   no hay ninguno.
//! - **`vulnerabilities`**: los `<script>` dentro de cada `<port>` y de
//!   `<hostscript>`. Un script genera hallazgos si su estado NSE es
//!   `VULNERABLE`/`LIKELY VULNERABLE`, o si menciona identificadores `CVE` y no
//!   dice `NOT VULNERABLE`. Se emite un [`VulnFinding`] por cada CVE distinto
//!   encontrado (en el `output` o en los `<elem>`), o uno solo con `id: None`
//!   si el script reporta vulnerabilidad sin CVE. `severity` se infiere de
//!   `risk factor:`/`severity:`, del `cvss` más alto de los `<elem>`, o del
//!   marcador `VULNERABLE (Exploitable)`; si no hay señal, [`Severity::Unknown`].
//!   `description` es el `output` del script recortado a
//!   [`MAX_DESCRIPTION_LEN`] caracteres. Scripts que reportan una debilidad sin
//!   estado NSE ni CVE (p. ej. `http-trace`) no se clasifican como hallazgos.
//! - **host caído** (`<host><status state="down">`): se devuelve un
//!   [`ScanResult`] con `ports` y `vulnerabilities` vacíos.
//! - **sin ningún `<host>`** en el `<nmaprun>` (objetivo caído sin `-v`, o
//!   escaneo sin resultados): [`ParseError::UnexpectedStructure`] — sin
//!   `<host>` no hay dirección con la que construir el [`ScanResult`], y un
//!   objetivo inalcanzable es un fallo que el pipeline debe poder distinguir.
//! - **varios `<host>`**: [`ParseError::MultipleHosts`]. El pipeline escanea
//!   una sola IP, así que siempre debería haber exactamente uno.

use std::net::IpAddr;

use roxmltree::{Document, Node, ParsingOptions};
use time::OffsetDateTime;

use crate::domain::{
    PortFinding, PortState, Protocol, ScanResult, Severity, VulnFinding, VulnSource,
};

/// Número máximo de caracteres que se conservan de la salida de un script NSE
/// en [`VulnFinding::description`]. Las salidas de scripts agregadores como
/// `vulners` pueden tener miles de líneas; se recortan a un tamaño manejable.
pub const MAX_DESCRIPTION_LEN: usize = 800;

/// Error de parseo del XML de `nmap`. Nunca se produce un `panic!`: toda
/// entrada inesperada se transforma en una de estas variantes.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// El texto no es XML bien formado. Envuelve el mensaje del parser XML.
    #[error("XML malformado: {0}")]
    MalformedXml(String),
    /// El XML es válido pero no tiene la forma de un informe de `nmap`: falta
    /// un elemento o atributo esperado, o es de una versión de `nmap` cuyo
    /// esquema no reconocemos.
    #[error("estructura de XML de nmap inesperada: {detail}")]
    UnexpectedStructure {
        /// Descripción de qué se esperaba y no se encontró.
        detail: String,
    },
    /// Un elemento/atributo está presente pero su valor no se puede
    /// interpretar (p. ej. `portid` no numérico, `time` no es un epoch válido,
    /// `addr` no es una IP).
    #[error("valor inválido en '{field}': {value}")]
    InvalidValue {
        /// Ruta del campo dentro del XML (p. ej. `port@portid`).
        field: String,
        /// Valor crudo que no se pudo interpretar.
        value: String,
    },
    /// El `<nmaprun>` contiene más de un `<host>`. El pipeline escanea una
    /// única IP, así que esto indica una entrada inesperada.
    #[error("el XML contiene múltiples <host>; se esperaba exactamente uno")]
    MultipleHosts,
}

/// Parsea el XML de un escaneo de `nmap` (`-oX`) y lo convierte en un
/// [`ScanResult`].
///
/// Es una función pura y síncrona: no hace IO ni bloquea.
///
/// # Errores
///
/// Devuelve [`ParseError`] si el texto no es XML bien formado
/// ([`ParseError::MalformedXml`]), si no tiene la estructura de un informe de
/// `nmap` ([`ParseError::UnexpectedStructure`]), si algún valor no se puede
/// interpretar ([`ParseError::InvalidValue`]) o si hay más de un `<host>`
/// ([`ParseError::MultipleHosts`]). Nunca hace `panic!`.
pub fn parse(xml: &str) -> Result<ScanResult, ParseError> {
    // `nmap` emite `<!DOCTYPE nmaprun>` (sin subconjunto interno de entidades);
    // roxmltree rechaza cualquier DTD salvo que se habilite explícitamente.
    let options = ParsingOptions {
        allow_dtd: true,
        ..ParsingOptions::default()
    };
    let doc = Document::parse_with_options(xml, options)
        .map_err(|e| ParseError::MalformedXml(e.to_string()))?;
    let root = doc.root_element();

    if root.tag_name().name() != "nmaprun" {
        return Err(ParseError::UnexpectedStructure {
            detail: format!(
                "elemento raíz esperado <nmaprun>, encontrado <{}>",
                root.tag_name().name()
            ),
        });
    }

    let scanned_at = parse_scanned_at(&root)?;

    let hosts: Vec<Node> = root
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == "host")
        .collect();

    let host_node = match hosts.as_slice() {
        [] => {
            return Err(ParseError::UnexpectedStructure {
                detail: "el <nmaprun> no contiene ningún <host> (objetivo inalcanzable \
                         o escaneo sin resultados)"
                    .to_owned(),
            });
        }
        [only] => *only,
        _ => return Err(ParseError::MultipleHosts),
    };

    let host = parse_host_address(&host_node)?;

    if !host_is_up(&host_node) {
        return Ok(ScanResult {
            host,
            ports: Vec::new(),
            vulnerabilities: Vec::new(),
            scanned_at,
        });
    }

    let ports = parse_ports(&host_node)?;
    let mut vulnerabilities = collect_port_vulns(&host_node);
    vulnerabilities.extend(collect_hostscript_vulns(&host_node));

    Ok(ScanResult {
        host,
        ports,
        vulnerabilities,
        scanned_at,
    })
}

fn children<'a, 'input>(
    node: &Node<'a, 'input>,
    name: &'static str,
) -> impl Iterator<Item = Node<'a, 'input>> {
    node.children()
        .filter(move |n| n.is_element() && n.tag_name().name() == name)
}

fn parse_scanned_at(root: &Node) -> Result<OffsetDateTime, ParseError> {
    let epoch_str = root
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "finished")
        .and_then(|n| n.attribute("time"))
        .or_else(|| root.attribute("start"))
        .ok_or(ParseError::UnexpectedStructure {
            detail: "falta <runstats><finished time> y el atributo start de <nmaprun>".to_owned(),
        })?;

    let epoch: i64 = epoch_str.parse().map_err(|_| ParseError::InvalidValue {
        field: "runstats/finished@time".to_owned(),
        value: epoch_str.to_owned(),
    })?;

    OffsetDateTime::from_unix_timestamp(epoch).map_err(|_| ParseError::InvalidValue {
        field: "runstats/finished@time".to_owned(),
        value: epoch_str.to_owned(),
    })
}

fn parse_host_address(host: &Node) -> Result<IpAddr, ParseError> {
    for addr in children(host, "address") {
        if !matches!(addr.attribute("addrtype"), Some("ipv4") | Some("ipv6")) {
            continue;
        }
        let value = addr
            .attribute("addr")
            .ok_or(ParseError::UnexpectedStructure {
                detail: "<address> sin atributo addr".to_owned(),
            })?;
        return value.parse().map_err(|_| ParseError::InvalidValue {
            field: "host/address@addr".to_owned(),
            value: value.to_owned(),
        });
    }

    Err(ParseError::UnexpectedStructure {
        detail: "el <host> no tiene <address addrtype=\"ipv4|ipv6\">".to_owned(),
    })
}

fn host_is_up(host: &Node) -> bool {
    children(host, "status")
        .next()
        .and_then(|s| s.attribute("state"))
        .map(|state| state == "up")
        .unwrap_or(true)
}

fn parse_ports(host: &Node) -> Result<Vec<PortFinding>, ParseError> {
    let Some(ports_node) = children(host, "ports").next() else {
        return Ok(Vec::new());
    };

    children(&ports_node, "port")
        .map(|port| parse_port(&port))
        .collect()
}

fn parse_port(port: &Node) -> Result<PortFinding, ParseError> {
    let portid = port
        .attribute("portid")
        .ok_or(ParseError::UnexpectedStructure {
            detail: "un <port> no tiene el atributo portid".to_owned(),
        })?;
    let port_num: u16 = portid.parse().map_err(|_| ParseError::InvalidValue {
        field: "port@portid".to_owned(),
        value: portid.to_owned(),
    })?;

    let protocol = match port.attribute("protocol") {
        Some("tcp") => Protocol::Tcp,
        Some("udp") => Protocol::Udp,
        Some(other) => {
            return Err(ParseError::InvalidValue {
                field: "port@protocol".to_owned(),
                value: other.to_owned(),
            });
        }
        None => {
            return Err(ParseError::UnexpectedStructure {
                detail: format!("el <port {portid}> no tiene el atributo protocol"),
            });
        }
    };

    let state_raw = children(port, "state")
        .next()
        .and_then(|n| n.attribute("state"))
        .ok_or(ParseError::UnexpectedStructure {
            detail: format!("el <port {portid}> no tiene <state state=..>"),
        })?;
    let state = parse_state(state_raw).ok_or(ParseError::InvalidValue {
        field: "port/state@state".to_owned(),
        value: state_raw.to_owned(),
    })?;

    let service_node = children(port, "service").next();
    let service = service_node
        .and_then(|s| s.attribute("name"))
        .map(str::to_owned);
    let version = service_node.and_then(|s| build_version(&s));
    let cpes = service_node.map(|s| collect_cpes(&s)).unwrap_or_default();

    Ok(PortFinding {
        port: port_num,
        protocol,
        state,
        service,
        version,
        cpes,
    })
}

fn collect_cpes(service: &Node) -> Vec<String> {
    children(service, "cpe")
        .filter_map(|c| c.text())
        .map(|t| t.trim().to_owned())
        .filter(|t| !t.is_empty())
        .collect()
}

fn parse_state(raw: &str) -> Option<PortState> {
    Some(match raw {
        "open" => PortState::Open,
        "closed" => PortState::Closed,
        "filtered" => PortState::Filtered,
        "unfiltered" => PortState::Unfiltered,
        "open|filtered" => PortState::OpenFiltered,
        "closed|filtered" => PortState::ClosedFiltered,
        _ => return None,
    })
}

fn build_version(service: &Node) -> Option<String> {
    let attr = |name| {
        service
            .attribute(name)
            .map(str::trim)
            .filter(|s| !s.is_empty())
    };

    let mut rendered = String::new();
    for part in [attr("product"), attr("version")].into_iter().flatten() {
        if !rendered.is_empty() {
            rendered.push(' ');
        }
        rendered.push_str(part);
    }
    if let Some(extra) = attr("extrainfo") {
        if rendered.is_empty() {
            rendered.push_str(extra);
        } else {
            rendered.push_str(" (");
            rendered.push_str(extra);
            rendered.push(')');
        }
    }

    (!rendered.is_empty()).then_some(rendered)
}

fn collect_port_vulns(host: &Node) -> Vec<VulnFinding> {
    let Some(ports_node) = children(host, "ports").next() else {
        return Vec::new();
    };

    children(&ports_node, "port")
        .flat_map(|port| {
            children(&port, "script")
                .flat_map(|script| vulns_from_script(&script))
                .collect::<Vec<_>>()
        })
        .collect()
}

fn collect_hostscript_vulns(host: &Node) -> Vec<VulnFinding> {
    children(host, "hostscript")
        .flat_map(|hs| {
            children(&hs, "script")
                .flat_map(|script| vulns_from_script(&script))
                .collect::<Vec<_>>()
        })
        .collect()
}

fn vulns_from_script(script: &Node) -> Vec<VulnFinding> {
    let Some(nse_script) = script.attribute("id").map(str::to_owned) else {
        return Vec::new();
    };
    let output = script.attribute("output").unwrap_or_default();

    let mut haystack = String::from(output);
    let mut max_cvss: Option<f64> = None;
    let mut state_is_vulnerable = false;

    for elem in script
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "elem")
    {
        let Some(text) = elem.text() else { continue };
        haystack.push('\n');
        haystack.push_str(text);

        match elem.attribute("key") {
            Some("cvss") | Some("cvss_score") | Some("cvssv2") | Some("cvssv3") => {
                if let Ok(score) = text.trim().parse::<f64>() {
                    max_cvss = Some(max_cvss.map_or(score, |m: f64| m.max(score)));
                }
            }
            Some("state") => {
                let t = text.trim();
                if t.starts_with("VULNERABLE") || t.starts_with("LIKELY VULNERABLE") {
                    state_is_vulnerable = true;
                }
            }
            _ => {}
        }
    }

    let vulnerable = state_is_vulnerable || haystack.contains("State: VULNERABLE");
    let cves = extract_cves(&haystack);
    let says_not_vulnerable = haystack.contains("NOT VULNERABLE");

    let is_finding = vulnerable || (!cves.is_empty() && !says_not_vulnerable);
    if !is_finding {
        return Vec::new();
    }

    let severity = classify_severity(&haystack, max_cvss);
    let description = truncate(output.trim(), MAX_DESCRIPTION_LEN);

    if cves.is_empty() {
        vec![VulnFinding {
            id: None,
            severity,
            description,
            nse_script,
            source: VulnSource::NmapNse,
            references: Vec::new(),
        }]
    } else {
        cves.into_iter()
            .map(|cve| VulnFinding {
                id: Some(cve),
                severity,
                description: description.clone(),
                nse_script: nse_script.clone(),
                source: VulnSource::NmapNse,
                references: Vec::new(),
            })
            .collect()
    }
}

fn extract_cves(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();

    for (start, _) in text.match_indices("CVE-") {
        let rest = &text[start + "CVE-".len()..];
        let year: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if year.len() != 4 {
            continue;
        }
        let after_year = &rest[year.len()..];
        let Some(number_part) = after_year.strip_prefix('-') else {
            continue;
        };
        let number: String = number_part
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        if number.is_empty() {
            continue;
        }

        let cve = format!("CVE-{year}-{number}");
        if !out.contains(&cve) {
            out.push(cve);
        }
    }

    out
}

fn classify_severity(haystack: &str, max_cvss: Option<f64>) -> Severity {
    let lower = haystack.to_lowercase();

    for (needle, severity) in [
        ("critical", Severity::Critical),
        ("high", Severity::High),
        ("medium", Severity::Medium),
        ("low", Severity::Low),
    ] {
        if lower.contains(&format!("risk factor: {needle}"))
            || lower.contains(&format!("severity: {needle}"))
        {
            return severity;
        }
    }

    if let Some(score) = max_cvss {
        return if score >= 9.0 {
            Severity::Critical
        } else if score >= 7.0 {
            Severity::High
        } else if score >= 4.0 {
            Severity::Medium
        } else if score > 0.0 {
            Severity::Low
        } else {
            Severity::Unknown
        };
    }

    if haystack.contains("VULNERABLE (Exploitable)") {
        return Severity::High;
    }

    Severity::Unknown
}

fn truncate(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_owned();
    }
    let head: String = text.chars().take(max_chars).collect();
    format!("{head}...")
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPEN_PORTS_XML: &str = include_str!("../tests/fixtures/open_ports_service_version.xml");
    const NO_OPEN_PORTS_XML: &str = include_str!("../tests/fixtures/no_open_ports.xml");
    const HOST_DOWN_XML: &str = include_str!("../tests/fixtures/host_down.xml");
    const VULN_FINDINGS_XML: &str = include_str!("../tests/fixtures/vuln_findings.xml");
    const MULTIPLE_HOSTS_XML: &str = include_str!("../tests/fixtures/multiple_hosts.xml");
    const NO_HOST_ELEMENT_XML: &str = include_str!("../tests/fixtures/no_host_element.xml");
    const FILTERED_PORTS_XML: &str = include_str!("../tests/fixtures/filtered_ports.xml");

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("IP de prueba válida")
    }

    fn port(result: &ScanResult, number: u16) -> &PortFinding {
        result
            .ports
            .iter()
            .find(|p| p.port == number)
            .unwrap_or_else(|| panic!("no se encontró el puerto {number}"))
    }

    #[test]
    fn parses_open_ports_with_service_and_version() {
        let result = parse(OPEN_PORTS_XML).expect("fixture parsea");

        assert_eq!(result.host, ip("172.18.0.2"));
        assert_eq!(result.vulnerabilities, Vec::new());
        assert_eq!(result.ports.len(), 3);

        let ssh = port(&result, 2222);
        assert_eq!(ssh.protocol, Protocol::Tcp);
        assert_eq!(ssh.state, PortState::Open);
        assert_eq!(ssh.service.as_deref(), Some("ssh"));
        assert_eq!(ssh.version.as_deref(), Some("OpenSSH 9.9 (protocol 2.0)"));
        assert_eq!(ssh.cpes, vec!["cpe:/a:openbsd:openssh:9.9".to_owned()]);

        let http = port(&result, 80);
        assert_eq!(http.state, PortState::Closed);
        assert_eq!(http.service.as_deref(), Some("http"));
        assert_eq!(http.version, None);
        assert!(http.cpes.is_empty());

        let ssh_low = port(&result, 22);
        assert_eq!(ssh_low.state, PortState::Closed);
        assert_eq!(ssh_low.service.as_deref(), Some("ssh"));
        assert_eq!(ssh_low.version, None);

        // <runstats><finished time="1787873449">
        assert_eq!(result.scanned_at.unix_timestamp(), 1_787_873_449);
    }

    #[test]
    fn parses_filtered_and_open_filtered_ports_end_to_end() {
        let result = parse(FILTERED_PORTS_XML).expect("fixture parsea");

        assert_eq!(result.host, ip("10.99.99.99"));
        assert_eq!(result.vulnerabilities, Vec::new());
        assert_eq!(result.ports.len(), 4);

        let ssh = port(&result, 22);
        assert_eq!(ssh.protocol, Protocol::Tcp);
        assert_eq!(ssh.state, PortState::Filtered);

        let http = port(&result, 80);
        assert_eq!(http.state, PortState::Filtered);

        let dns = port(&result, 53);
        assert_eq!(dns.protocol, Protocol::Udp);
        assert_eq!(dns.state, PortState::OpenFiltered);

        let snmp = port(&result, 161);
        assert_eq!(snmp.protocol, Protocol::Udp);
        assert_eq!(snmp.state, PortState::OpenFiltered);
    }

    #[test]
    fn parses_host_with_no_open_ports() {
        let result = parse(NO_OPEN_PORTS_XML).expect("fixture parsea");

        assert_eq!(result.host, ip("172.18.0.2"));
        assert_eq!(result.vulnerabilities, Vec::new());
        assert_eq!(result.ports.len(), 5);
        assert!(
            result.ports.iter().all(|p| p.state == PortState::Closed),
            "todos los puertos del fixture están cerrados: {:?}",
            result.ports
        );
        assert_eq!(port(&result, 21).service.as_deref(), Some("ftp"));
        assert!(result.ports.iter().all(|p| p.version.is_none()));
    }

    #[test]
    fn parses_host_down_as_empty_result() {
        let result = parse(HOST_DOWN_XML).expect("fixture parsea");

        assert_eq!(result.host, ip("172.18.0.253"));
        assert_eq!(result.ports, Vec::new());
        assert_eq!(result.vulnerabilities, Vec::new());
        assert_eq!(result.scanned_at.unix_timestamp(), 1_787_873_583);
    }

    #[test]
    fn parses_vulnerability_findings_from_vuln_scripts() {
        let result = parse(VULN_FINDINGS_XML).expect("fixture parsea");

        assert_eq!(result.host, ip("172.18.0.4"));

        let ftp = port(&result, 21);
        assert_eq!(ftp.state, PortState::Open);
        assert_eq!(ftp.service.as_deref(), Some("ftp"));
        assert_eq!(ftp.version.as_deref(), Some("vsftpd 2.3.4"));
        assert_eq!(ftp.cpes, vec!["cpe:/a:vsftpd:vsftpd:2.3.4".to_owned()]);

        assert!(
            result
                .vulnerabilities
                .iter()
                .all(|v| v.source == VulnSource::NmapNse),
            "los hallazgos del parser siempre son NmapNse: {:?}",
            result.vulnerabilities
        );

        let irc = port(&result, 6667);
        assert_eq!(irc.state, PortState::Open);
        assert_eq!(irc.service.as_deref(), Some("irc"));

        // `ftp-vsftpd-backdoor` (estado NSE VULNERABLE, con CVE) y `vulners`
        // (lista de CVEs con cvss). `irc-unrealircd-backdoor` sólo reporta un
        // error de conexión -> no es un hallazgo.
        let backdoor = result
            .vulnerabilities
            .iter()
            .find(|v| v.nse_script == "ftp-vsftpd-backdoor")
            .expect("hallazgo de ftp-vsftpd-backdoor");
        assert_eq!(backdoor.id.as_deref(), Some("CVE-2011-2523"));
        assert_eq!(backdoor.severity, Severity::High);
        assert!(backdoor
            .description
            .contains("vsFTPd version 2.3.4 backdoor"));
        assert!(backdoor.description.contains("CVE:CVE-2011-2523"));

        let vulners = result
            .vulnerabilities
            .iter()
            .find(|v| v.nse_script == "vulners")
            .expect("hallazgo de vulners");
        assert_eq!(vulners.id.as_deref(), Some("CVE-2011-2523"));
        assert_eq!(vulners.severity, Severity::Critical);
        assert!(vulners.description.chars().count() <= MAX_DESCRIPTION_LEN + 3);

        assert!(
            result
                .vulnerabilities
                .iter()
                .all(|v| v.nse_script != "irc-unrealircd-backdoor"),
            "irc-unrealircd-backdoor no debe generar hallazgos: {:?}",
            result.vulnerabilities
        );
    }

    #[test]
    fn parse_state_maps_every_raw_nmap_state() {
        assert_eq!(parse_state("open"), Some(PortState::Open));
        assert_eq!(parse_state("closed"), Some(PortState::Closed));
        assert_eq!(parse_state("filtered"), Some(PortState::Filtered));
        assert_eq!(parse_state("unfiltered"), Some(PortState::Unfiltered));
        assert_eq!(parse_state("open|filtered"), Some(PortState::OpenFiltered));
        assert_eq!(
            parse_state("closed|filtered"),
            Some(PortState::ClosedFiltered)
        );
        assert_eq!(parse_state("weird-new-state"), None);
    }

    #[test]
    fn parse_returns_error_on_malformed_xml() {
        // Cabecera de un informe real de nmap, cortada antes de cerrar
        // <nmaprun>: XML sin terminar.
        let truncated = &OPEN_PORTS_XML[..220];
        assert!(
            truncated.is_ascii(),
            "el corte cae en un límite de carácter"
        );

        match parse(truncated) {
            Err(ParseError::MalformedXml(_)) => {}
            other => panic!("se esperaba MalformedXml, se obtuvo {other:?}"),
        }
    }

    #[test]
    fn parse_returns_error_on_unexpected_structure() {
        let well_formed_non_nmap = "<report><scan done=\"true\"/></report>";

        match parse(well_formed_non_nmap) {
            Err(ParseError::UnexpectedStructure { detail }) => {
                assert!(detail.contains("nmaprun"), "detalle: {detail}");
            }
            other => panic!("se esperaba UnexpectedStructure, se obtuvo {other:?}"),
        }
    }

    #[test]
    fn parse_returns_error_when_nmaprun_has_no_host() {
        match parse(NO_HOST_ELEMENT_XML) {
            Err(ParseError::UnexpectedStructure { detail }) => {
                assert!(detail.contains("host"), "detalle: {detail}");
            }
            other => panic!("se esperaba UnexpectedStructure, se obtuvo {other:?}"),
        }
    }

    #[test]
    fn parse_returns_error_on_multiple_hosts() {
        match parse(MULTIPLE_HOSTS_XML) {
            Err(ParseError::MultipleHosts) => {}
            other => panic!("se esperaba MultipleHosts, se obtuvo {other:?}"),
        }
    }

    #[test]
    fn parse_reports_invalid_port_id_out_of_range() {
        // Se corrompe un fixture real: 65_536 no cabe en un u16.
        let corrupted = OPEN_PORTS_XML.replace("portid=\"2222\"", "portid=\"65536\"");

        match parse(&corrupted) {
            Err(ParseError::InvalidValue { field, value }) => {
                assert_eq!(field, "port@portid");
                assert_eq!(value, "65536");
            }
            other => panic!("se esperaba InvalidValue, se obtuvo {other:?}"),
        }
    }
}
