//! Diffing two scans of (ideally) the same target.
//!
//! This is one of the two correctness-critical modules (the other is the XML
//! parser): a wrong diff means a wrong security conclusion, so the logic is a
//! pure function with thorough unit tests.
//!
//! What we surface: hosts added/removed, host up/down changes, ports
//! opened/closed, and service (name/product/version) changes. Only *changes*
//! appear in the result; unchanged items are omitted.
//!
//! Not yet handled: TLS cert changes. nmap exposes certs via NSE `<script>`
//! output, which the parser does not read yet — deferred until NSE support
//! lands in M6.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::scan::{Host, Port, ScanResult};

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanDiff {
    /// Hosts with at least one change. Hosts that are identical are omitted.
    pub hosts: Vec<HostDiff>,
    /// True when the two scans are equivalent in everything we compare.
    pub unchanged: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostDiff {
    /// The host's display key (IPv4 preferred).
    pub host: String,
    /// "added" (only in new), "removed" (only in old), or "changed".
    pub status: String,
    /// Host up/down change, e.g. "up → down". None when it didn't change.
    pub state_change: Option<String>,
    /// Per-port changes (empty for a pure state change).
    pub ports: Vec<PortDiff>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortDiff {
    pub portid: u16,
    pub protocol: String,
    /// "opened", "closed", or "service-changed".
    pub kind: String,
    /// Human-readable detail, e.g. "closed → open" or "OpenSSH 8.9 → 9.0".
    pub detail: String,
}

/// Best display key for a host: its IPv4 address, else the first address,
/// else the first hostname, else a placeholder.
fn host_key(h: &Host) -> String {
    if let Some(v4) = h.addresses.iter().find(|a| a.addr_type == "ipv4") {
        return v4.addr.clone();
    }
    if let Some(first) = h.addresses.first() {
        return first.addr.clone();
    }
    if let Some(name) = h.hostnames.first() {
        return name.clone();
    }
    "(unknown)".to_string()
}

fn is_open(p: &Port) -> bool {
    p.state == "open"
}

fn service_label(p: &Port) -> String {
    match &p.service {
        None => String::new(),
        Some(s) => [
            s.name.as_deref(),
            s.product.as_deref(),
            s.version.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" "),
    }
}

fn label_or(p: &Port, fallback: &str) -> String {
    let l = service_label(p);
    if l.is_empty() {
        fallback.to_string()
    } else {
        l
    }
}

fn index_hosts(result: &ScanResult) -> BTreeMap<String, &Host> {
    result.hosts.iter().map(|h| (host_key(h), h)).collect()
}

fn index_ports(host: &Host) -> BTreeMap<(u16, String), &Port> {
    host.ports
        .iter()
        .map(|p| ((p.portid, p.protocol.clone()), p))
        .collect()
}

/// Diff two scans. Pure — no I/O.
pub fn diff_scans(old: &ScanResult, new: &ScanResult) -> ScanDiff {
    let old_hosts = index_hosts(old);
    let new_hosts = index_hosts(new);

    let keys: BTreeSet<&String> = old_hosts.keys().chain(new_hosts.keys()).collect();

    let mut hosts = Vec::new();
    for key in keys {
        match (old_hosts.get(key), new_hosts.get(key)) {
            (Some(o), Some(n)) => {
                let ports = diff_ports(o, n);
                let state_change = if o.state != n.state {
                    Some(format!("{} → {}", o.state, n.state))
                } else {
                    None
                };
                if !ports.is_empty() || state_change.is_some() {
                    hosts.push(HostDiff {
                        host: key.clone(),
                        status: "changed".to_string(),
                        state_change,
                        ports,
                    });
                }
            }
            (Some(o), None) => hosts.push(HostDiff {
                host: key.clone(),
                status: "removed".to_string(),
                state_change: None,
                // Previously-open ports are now gone.
                ports: open_ports_as(o, "closed"),
            }),
            (None, Some(n)) => hosts.push(HostDiff {
                host: key.clone(),
                status: "added".to_string(),
                state_change: None,
                ports: open_ports_as(n, "opened"),
            }),
            (None, None) => unreachable!("key came from one of the maps"),
        }
    }

    let unchanged = hosts.is_empty();
    ScanDiff { hosts, unchanged }
}

/// For an added/removed host, list its open ports all under one `kind`.
fn open_ports_as(host: &Host, kind: &str) -> Vec<PortDiff> {
    host.ports
        .iter()
        .filter(|p| is_open(p))
        .map(|p| PortDiff {
            portid: p.portid,
            protocol: p.protocol.clone(),
            kind: kind.to_string(),
            detail: label_or(p, kind),
        })
        .collect()
}

fn diff_ports(old: &Host, new: &Host) -> Vec<PortDiff> {
    let old_ports = index_ports(old);
    let new_ports = index_ports(new);
    let keys: BTreeSet<&(u16, String)> = old_ports.keys().chain(new_ports.keys()).collect();

    let mut diffs = Vec::new();
    for key in keys {
        let o = old_ports.get(key).copied();
        let n = new_ports.get(key).copied();
        let old_open = o.map(is_open).unwrap_or(false);
        let new_open = n.map(is_open).unwrap_or(false);

        let (portid, protocol) = (key.0, key.1.clone());

        if !old_open && new_open {
            let np = n.unwrap();
            diffs.push(PortDiff {
                portid,
                protocol,
                kind: "opened".to_string(),
                detail: label_or(np, "open"),
            });
        } else if old_open && !new_open {
            let op = o.unwrap();
            diffs.push(PortDiff {
                portid,
                protocol,
                kind: "closed".to_string(),
                detail: {
                    let was = label_or(op, "open");
                    format!("was {was}")
                },
            });
        } else if old_open && new_open {
            let (op, np) = (o.unwrap(), n.unwrap());
            let (ol, nl) = (service_label(op), service_label(np));
            if ol != nl {
                diffs.push(PortDiff {
                    portid,
                    protocol,
                    kind: "service-changed".to_string(),
                    detail: format!(
                        "{} → {}",
                        if ol.is_empty() { "(unknown)" } else { &ol },
                        if nl.is_empty() { "(unknown)" } else { &nl },
                    ),
                });
            }
        }
        // both closed/absent → not a change
    }
    diffs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::parse_nmap_xml;

    // Minimal nmap-shaped XML builder. Port: (portid, state, service, version);
    // host: (addr, state, &[ports]).
    type PortSpec<'a> = (u16, &'a str, &'a str, &'a str);
    type HostSpec<'a> = (&'a str, &'a str, &'a [PortSpec<'a>]);

    fn scan_xml(hosts: &[HostSpec]) -> String {
        let mut s = String::from(
            r#"<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun scanner="nmap" version="7.94">"#,
        );
        for (addr, state, ports) in hosts {
            s.push_str(&format!(
                r#"<host><status state="{state}"/><address addr="{addr}" addrtype="ipv4"/><ports>"#
            ));
            for (portid, pstate, name, version) in *ports {
                s.push_str(&format!(
                    r#"<port protocol="tcp" portid="{portid}"><state state="{pstate}"/>"#
                ));
                if !name.is_empty() {
                    s.push_str(&format!(r#"<service name="{name}" version="{version}"/>"#));
                }
                s.push_str("</port>");
            }
            s.push_str("</ports></host>");
        }
        s.push_str("</nmaprun>");
        s
    }

    fn find_host<'a>(d: &'a ScanDiff, host: &str) -> &'a HostDiff {
        d.hosts
            .iter()
            .find(|h| h.host == host)
            .expect("host present")
    }
    fn find_port(h: &HostDiff, portid: u16) -> &PortDiff {
        h.ports
            .iter()
            .find(|p| p.portid == portid)
            .expect("port present")
    }

    #[test]
    fn identical_scans_are_unchanged() {
        let xml = scan_xml(&[("10.0.0.1", "up", &[(22, "open", "ssh", "8.9")])]);
        let a = parse_nmap_xml(&xml).unwrap();
        let b = parse_nmap_xml(&xml).unwrap();
        let d = diff_scans(&a, &b);
        assert!(d.unchanged);
        assert!(d.hosts.is_empty());
    }

    #[test]
    fn detects_opened_closed_and_version_change() {
        let old = parse_nmap_xml(&scan_xml(&[(
            "10.0.0.1",
            "up",
            &[
                (22, "open", "ssh", "8.9"),
                (80, "open", "http", "1.18"),
                (443, "open", "https", ""),
            ],
        )]))
        .unwrap();
        // new: 22 version bump, 80 gone (closed), 8080 opened, 443 unchanged.
        let new = parse_nmap_xml(&scan_xml(&[(
            "10.0.0.1",
            "up",
            &[
                (22, "open", "ssh", "9.0"),
                (443, "open", "https", ""),
                (8080, "open", "http-proxy", ""),
            ],
        )]))
        .unwrap();

        let d = diff_scans(&old, &new);
        assert!(!d.unchanged);
        let h = find_host(&d, "10.0.0.1");
        assert_eq!(h.status, "changed");

        assert_eq!(find_port(h, 22).kind, "service-changed");
        assert_eq!(find_port(h, 22).detail, "ssh 8.9 → ssh 9.0");
        assert_eq!(find_port(h, 80).kind, "closed");
        assert_eq!(find_port(h, 8080).kind, "opened");
        // 443 unchanged → not listed.
        assert!(h.ports.iter().all(|p| p.portid != 443));
    }

    #[test]
    fn detects_added_and_removed_hosts() {
        let old = parse_nmap_xml(&scan_xml(&[
            ("10.0.0.1", "up", &[(22, "open", "ssh", "8.9")]),
            ("10.0.0.2", "up", &[(80, "open", "http", "1.18")]),
        ]))
        .unwrap();
        let new = parse_nmap_xml(&scan_xml(&[
            ("10.0.0.1", "up", &[(22, "open", "ssh", "8.9")]),
            ("10.0.0.3", "up", &[(443, "open", "https", "")]),
        ]))
        .unwrap();

        let d = diff_scans(&old, &new);
        assert_eq!(find_host(&d, "10.0.0.2").status, "removed");
        assert_eq!(find_host(&d, "10.0.0.3").status, "added");
        // 10.0.0.1 unchanged → absent.
        assert!(d.hosts.iter().all(|h| h.host != "10.0.0.1"));
    }

    #[test]
    fn detects_host_state_change() {
        let old = parse_nmap_xml(&scan_xml(&[(
            "10.0.0.1",
            "up",
            &[(22, "open", "ssh", "8.9")],
        )]))
        .unwrap();
        let new = parse_nmap_xml(&scan_xml(&[("10.0.0.1", "down", &[])])).unwrap();
        let d = diff_scans(&old, &new);
        let h = find_host(&d, "10.0.0.1");
        assert_eq!(h.state_change.as_deref(), Some("up → down"));
        // The port that vanished with the host going down shows as closed.
        assert_eq!(find_port(h, 22).kind, "closed");
    }
}
