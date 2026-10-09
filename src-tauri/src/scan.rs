//! Nmap integration: spawn the real `nmap` binary with `-oX -` and parse its
//! XML output into typed structs.
//!
//! Design rules (see CLAUDE.md):
//! - We never reimplement scanning; we shell out to `nmap`.
//! - We parse the XML with a real XML parser (`roxmltree`), never regex.
//! - Parsing is a pure function (`parse_nmap_xml`) so it is unit-testable
//!   without `nmap` installed.

use serde::Serialize;
use std::process::Command;

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// A fully parsed nmap run.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanResult {
    /// The scanner name reported by nmap (usually "nmap").
    pub scanner: String,
    /// The exact command line nmap recorded for this run.
    pub args: String,
    /// The nmap version string (e.g. "7.94SVN").
    pub version: String,
    /// Scan start time as a Unix epoch (seconds), if present.
    pub start: Option<i64>,
    /// Every `<host>` in the run (hosthints are ignored).
    pub hosts: Vec<Host>,
    /// Run summary from `<runstats>`, if present.
    pub summary: Option<RunStats>,
}

/// Summary statistics from `<runstats>`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunStats {
    pub hosts_up: u32,
    pub hosts_down: u32,
    pub hosts_total: u32,
    /// Wall-clock seconds the scan took, if reported.
    pub elapsed_secs: Option<f64>,
    /// nmap's own exit descriptor (e.g. "success").
    pub exit: Option<String>,
    /// Human-readable one-line summary.
    pub summary: Option<String>,
}

/// A single scanned host.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Host {
    /// "up" or "down".
    pub state: String,
    /// Why nmap concluded that state (e.g. "syn-ack", "no-response").
    pub reason: Option<String>,
    /// All addresses for this host (ipv4, ipv6, mac).
    pub addresses: Vec<Address>,
    /// Unique hostnames, in first-seen order.
    pub hostnames: Vec<String>,
    /// Ports nmap reported individually (the `<extraports>` summary is skipped).
    pub ports: Vec<Port>,
}

/// One address of a host.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Address {
    pub addr: String,
    /// "ipv4", "ipv6", or "mac".
    pub addr_type: String,
    /// MAC vendor, when nmap resolved one.
    pub vendor: Option<String>,
}

/// A single port result.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Port {
    /// "tcp" or "udp".
    pub protocol: String,
    pub portid: u16,
    /// "open", "closed", "filtered", etc.
    pub state: String,
    pub reason: Option<String>,
    /// Service info, present when nmap identified one.
    pub service: Option<Service>,
}

/// Service identification for a port.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    pub name: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extrainfo: Option<String>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from parsing nmap XML.
#[derive(Debug)]
pub enum ParseError {
    Xml(roxmltree::Error),
    /// The document root was not `<nmaprun>`.
    MissingRoot,
    /// A `<port>` had a missing or non-numeric `portid`.
    BadPortId(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Xml(e) => write!(f, "invalid XML: {e}"),
            ParseError::MissingRoot => write!(f, "expected <nmaprun> root element"),
            ParseError::BadPortId(s) => write!(f, "invalid portid: {s:?}"),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<roxmltree::Error> for ParseError {
    fn from(e: roxmltree::Error) -> Self {
        ParseError::Xml(e)
    }
}

/// Errors from running a scan (spawn + parse).
#[derive(Debug)]
pub enum ScanError {
    /// The target was empty or looked like a flag (flag-injection guard).
    InvalidTarget(String),
    /// Failed to spawn `nmap` (e.g. not installed / not on PATH).
    Spawn(std::io::Error),
    /// nmap ran but exited non-zero.
    NmapFailed { code: Option<i32>, stderr: String },
    /// nmap's stdout was not valid UTF-8.
    Utf8(std::string::FromUtf8Error),
    /// The XML parsed from nmap's stdout was invalid.
    Parse(ParseError),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::InvalidTarget(t) => {
                write!(
                    f,
                    "invalid target {t:?}: must be non-empty and not start with '-'"
                )
            }
            ScanError::Spawn(e) => write!(f, "could not run nmap: {e} (is nmap installed?)"),
            ScanError::NmapFailed { code, stderr } => {
                write!(f, "nmap exited with {code:?}: {}", stderr.trim())
            }
            ScanError::Utf8(e) => write!(f, "nmap output was not valid UTF-8: {e}"),
            ScanError::Parse(e) => write!(f, "could not parse nmap output: {e}"),
        }
    }
}

impl std::error::Error for ScanError {}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

type Node<'a> = roxmltree::Node<'a, 'a>;

/// Parse nmap `-oX` XML into a [`ScanResult`]. Pure — no process spawning.
pub fn parse_nmap_xml(xml: &str) -> Result<ScanResult, ParseError> {
    // nmap emits `<!DOCTYPE nmaprun>`, so we must allow a DTD. This is safe:
    // the doctype declares no entities, and roxmltree never expands external
    // entities, so there is no XXE / entity-expansion exposure here.
    let opts = roxmltree::ParsingOptions {
        allow_dtd: true,
        ..Default::default()
    };
    let doc = roxmltree::Document::parse_with_options(xml, opts)?;
    let root = doc.root_element();
    if root.tag_name().name() != "nmaprun" {
        return Err(ParseError::MissingRoot);
    }

    let scanner = attr(root, "scanner").unwrap_or_default();
    let args = attr(root, "args").unwrap_or_default();
    let version = attr(root, "version").unwrap_or_default();
    let start = attr(root, "start").and_then(|s| s.parse::<i64>().ok());

    let mut hosts = Vec::new();
    let mut summary = None;
    for child in root.children().filter(|n| n.is_element()) {
        match child.tag_name().name() {
            // Only real <host> elements. <hosthint> is deliberately skipped.
            "host" => hosts.push(parse_host(child)?),
            "runstats" => summary = Some(parse_runstats(child)),
            _ => {}
        }
    }

    Ok(ScanResult {
        scanner,
        args,
        version,
        start,
        hosts,
        summary,
    })
}

fn parse_host(node: Node) -> Result<Host, ParseError> {
    let mut state = String::new();
    let mut reason = None;
    let mut addresses = Vec::new();
    let mut hostnames: Vec<String> = Vec::new();
    let mut ports = Vec::new();

    for child in node.children().filter(|n| n.is_element()) {
        match child.tag_name().name() {
            "status" => {
                state = attr(child, "state").unwrap_or_default();
                reason = attr(child, "reason");
            }
            "address" => {
                if let Some(addr) = attr(child, "addr") {
                    addresses.push(Address {
                        addr,
                        addr_type: attr(child, "addrtype").unwrap_or_default(),
                        vendor: attr(child, "vendor"),
                    });
                }
            }
            "hostnames" => {
                for hn in child
                    .children()
                    .filter(|n| n.is_element() && n.tag_name().name() == "hostname")
                {
                    if let Some(name) = attr(hn, "name") {
                        if !hostnames.contains(&name) {
                            hostnames.push(name);
                        }
                    }
                }
            }
            "ports" => {
                for p in child
                    .children()
                    .filter(|n| n.is_element() && n.tag_name().name() == "port")
                {
                    ports.push(parse_port(p)?);
                }
            }
            _ => {}
        }
    }

    Ok(Host {
        state,
        reason,
        addresses,
        hostnames,
        ports,
    })
}

fn parse_port(node: Node) -> Result<Port, ParseError> {
    let protocol = attr(node, "protocol").unwrap_or_default();
    let portid_raw = attr(node, "portid").unwrap_or_default();
    let portid: u16 = portid_raw
        .parse()
        .map_err(|_| ParseError::BadPortId(portid_raw.clone()))?;

    let mut state = String::new();
    let mut reason = None;
    let mut service = None;

    for child in node.children().filter(|n| n.is_element()) {
        match child.tag_name().name() {
            "state" => {
                state = attr(child, "state").unwrap_or_default();
                reason = attr(child, "reason");
            }
            "service" => {
                service = Some(Service {
                    name: attr(child, "name"),
                    product: attr(child, "product"),
                    version: attr(child, "version"),
                    extrainfo: attr(child, "extrainfo"),
                });
            }
            _ => {}
        }
    }

    Ok(Port {
        protocol,
        portid,
        state,
        reason,
        service,
    })
}

fn parse_runstats(node: Node) -> RunStats {
    let mut hosts_up = 0;
    let mut hosts_down = 0;
    let mut hosts_total = 0;
    let mut elapsed_secs = None;
    let mut exit = None;
    let mut summary = None;

    for child in node.children().filter(|n| n.is_element()) {
        match child.tag_name().name() {
            "finished" => {
                elapsed_secs = attr(child, "elapsed").and_then(|s| s.parse::<f64>().ok());
                exit = attr(child, "exit");
                summary = attr(child, "summary");
            }
            "hosts" => {
                hosts_up = attr(child, "up").and_then(|s| s.parse().ok()).unwrap_or(0);
                hosts_down = attr(child, "down")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                hosts_total = attr(child, "total")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            }
            _ => {}
        }
    }

    RunStats {
        hosts_up,
        hosts_down,
        hosts_total,
        elapsed_secs,
        exit,
        summary,
    }
}

/// Small helper: read an attribute as an owned String.
fn attr(node: Node, name: &str) -> Option<String> {
    node.attribute(name).map(|s| s.to_string())
}

// ---------------------------------------------------------------------------
// Running nmap
// ---------------------------------------------------------------------------

/// Run an nmap scan against `target` with the given `flags`, returning the
/// parsed result.
///
/// We always append `-oX -` ourselves (XML to stdout); callers must not pass
/// their own output flags.
///
/// Security: we use [`Command`] with explicit arguments (no shell), so there
/// is no shell-injection vector. `target` is the untrusted, free-text field,
/// so we reject one that is empty or starts with `-` to prevent it being
/// interpreted as an nmap flag. `flags` are expected to be app-controlled
/// presets, not free text.
pub fn run_scan(target: &str, flags: &[String]) -> Result<ScanResult, ScanError> {
    if target.trim().is_empty() || target.starts_with('-') {
        return Err(ScanError::InvalidTarget(target.to_string()));
    }

    let output = Command::new("nmap")
        .args(flags)
        .arg("-oX")
        .arg("-")
        .arg(target)
        .output()
        .map_err(ScanError::Spawn)?;

    if !output.status.success() {
        return Err(ScanError::NmapFailed {
            code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }

    let xml = String::from_utf8(output.stdout).map_err(ScanError::Utf8)?;
    parse_nmap_xml(&xml).map_err(ScanError::Parse)
}

/// Tauri command wrapper. Errors are stringified for the frontend.
#[tauri::command]
pub fn run_nmap_scan(target: String, flags: Vec<String>) -> Result<ScanResult, String> {
    run_scan(&target, &flags).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Tests (do NOT require nmap to be installed)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const LOCALHOST_CONNECT: &str = include_str!("../tests/fixtures/localhost-connect.xml");
    const MULTI_HOST_VERSION: &str = include_str!("../tests/fixtures/multi-host-version.xml");

    #[test]
    fn parses_localhost_connect_scan() {
        let r = parse_nmap_xml(LOCALHOST_CONNECT).expect("should parse");
        assert_eq!(r.scanner, "nmap");
        assert_eq!(r.version, "7.94SVN");
        assert_eq!(r.hosts.len(), 1);

        let h = &r.hosts[0];
        assert_eq!(h.state, "up");
        assert_eq!(h.reason.as_deref(), Some("syn-ack"));
        assert_eq!(h.addresses.len(), 1);
        assert_eq!(h.addresses[0].addr, "127.0.0.1");
        assert_eq!(h.addresses[0].addr_type, "ipv4");
        // Duplicate "localhost" (user + PTR) is de-duplicated to one entry.
        assert_eq!(h.hostnames, vec!["localhost".to_string()]);

        // 8 individually-listed open ports; <extraports> (92 closed) is skipped.
        assert_eq!(h.ports.len(), 8);
        let p80 = h.ports.iter().find(|p| p.portid == 80).unwrap();
        assert_eq!(p80.protocol, "tcp");
        assert_eq!(p80.state, "open");
        assert_eq!(p80.service.as_ref().unwrap().name.as_deref(), Some("http"));
        let p3306 = h.ports.iter().find(|p| p.portid == 3306).unwrap();
        assert_eq!(
            p3306.service.as_ref().unwrap().name.as_deref(),
            Some("mysql")
        );

        let s = r.summary.unwrap();
        assert_eq!((s.hosts_up, s.hosts_down, s.hosts_total), (1, 0, 1));
        assert_eq!(s.exit.as_deref(), Some("success"));
    }

    #[test]
    fn parses_multi_host_with_versions_and_down_host() {
        let r = parse_nmap_xml(MULTI_HOST_VERSION).expect("should parse");
        assert_eq!(r.hosts.len(), 2);

        // Host 0: up, has an ipv4 + a mac address, two versioned services.
        let up = &r.hosts[0];
        assert_eq!(up.state, "up");
        assert_eq!(up.addresses.len(), 2);
        let mac = up.addresses.iter().find(|a| a.addr_type == "mac").unwrap();
        assert_eq!(mac.vendor.as_deref(), Some("Example Vendor"));

        let ssh = up.ports.iter().find(|p| p.portid == 22).unwrap();
        let svc = ssh.service.as_ref().unwrap();
        assert_eq!(svc.name.as_deref(), Some("ssh"));
        assert_eq!(svc.product.as_deref(), Some("OpenSSH"));
        assert_eq!(svc.version.as_deref(), Some("8.9p1 Ubuntu 3ubuntu0.4"));
        assert_eq!(svc.extrainfo.as_deref(), Some("Ubuntu Linux; protocol 2.0"));

        let http = up.ports.iter().find(|p| p.portid == 80).unwrap();
        let hsvc = http.service.as_ref().unwrap();
        assert_eq!(hsvc.product.as_deref(), Some("nginx"));
        assert_eq!(hsvc.version.as_deref(), Some("1.18.0"));

        // Host 1: down, no ports.
        let down = &r.hosts[1];
        assert_eq!(down.state, "down");
        assert!(down.ports.is_empty());

        let s = r.summary.unwrap();
        assert_eq!((s.hosts_up, s.hosts_down, s.hosts_total), (1, 1, 2));
    }

    #[test]
    fn empty_run_has_no_hosts() {
        let xml = r#"<?xml version="1.0"?><nmaprun scanner="nmap" version="7.94"></nmaprun>"#;
        let r = parse_nmap_xml(xml).expect("should parse");
        assert!(r.hosts.is_empty());
        assert!(r.summary.is_none());
    }

    #[test]
    fn rejects_non_nmap_root() {
        let xml = r#"<?xml version="1.0"?><notnmap></notnmap>"#;
        assert!(matches!(parse_nmap_xml(xml), Err(ParseError::MissingRoot)));
    }

    #[test]
    fn rejects_bad_portid() {
        let xml = r#"<?xml version="1.0"?><nmaprun><host><status state="up"/>
            <ports><port protocol="tcp" portid="notaport"><state state="open"/></port></ports>
            </host></nmaprun>"#;
        assert!(matches!(parse_nmap_xml(xml), Err(ParseError::BadPortId(_))));
    }

    #[test]
    fn rejects_malformed_xml() {
        assert!(matches!(
            parse_nmap_xml("<nmaprun><host>"),
            Err(ParseError::Xml(_))
        ));
    }

    // --- run_scan guard tests (these return before spawning nmap) ---

    #[test]
    fn run_scan_rejects_empty_target() {
        assert!(matches!(
            run_scan("   ", &[]),
            Err(ScanError::InvalidTarget(_))
        ));
    }

    #[test]
    fn run_scan_rejects_flag_like_target() {
        // Prevents a free-text target from injecting an nmap flag.
        assert!(matches!(
            run_scan("-oG /tmp/evil", &[]),
            Err(ScanError::InvalidTarget(_))
        ));
    }
}
