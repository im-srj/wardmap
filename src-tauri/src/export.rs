//! Export a saved scan to a file: the raw XML, or one of our own renderings of
//! it. Pure functions over the parsed result, so no re-scan is ever needed and
//! everything is testable without nmap.
//!
//! The text formats follow nmap's `-oN` / `-oG` layout closely enough for
//! people and grep-based tooling, but they are rebuilt from the XML, so
//! details nmap's XML doesn't carry (e.g. latency) are absent. Each says so in
//! its header comment.

use serde::Deserialize;
use std::fmt::Write;

use crate::scan::{Host, Port, ScanResult, ScriptOutput};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// nmap's own XML, byte for byte as stored.
    Xml,
    Json,
    /// One row per port.
    Csv,
    /// Like `-oN`.
    Normal,
    /// Like `-oG`.
    Grepable,
    /// A standalone report page (inline CSS, no external resources).
    Html,
}

impl Format {
    pub fn extension(self) -> &'static str {
        match self {
            Format::Xml => "xml",
            Format::Json => "json",
            Format::Csv => "csv",
            Format::Normal => "nmap",
            Format::Grepable => "gnmap",
            Format::Html => "html",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Format::Xml => "nmap XML",
            Format::Json => "JSON",
            Format::Csv => "CSV",
            Format::Normal => "nmap normal output",
            Format::Grepable => "nmap grepable output",
            Format::Html => "HTML report",
        }
    }
}

/// Render a saved scan. `title` names it in the HTML report (its history
/// label); `raw_xml` is what was stored.
pub fn render(format: Format, title: &str, result: &ScanResult, raw_xml: &str) -> String {
    match format {
        Format::Xml => raw_xml.to_string(),
        Format::Json => serde_json::to_string_pretty(result).unwrap_or_default(),
        Format::Csv => csv(result),
        Format::Normal => normal(result),
        Format::Grepable => grepable(result),
        Format::Html => html(title, result),
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// The address nmap names a host by: IPv4, else IPv6, else whatever is first.
fn primary_addr(h: &Host) -> &str {
    ["ipv4", "ipv6"]
        .iter()
        .find_map(|t| h.addresses.iter().find(|a| a.addr_type == *t))
        .or(h.addresses.first())
        .map(|a| a.addr.as_str())
        .unwrap_or("")
}

/// "name (addr)" or just "addr", as in nmap's "Nmap scan report for …".
fn host_title(h: &Host) -> String {
    match h.hostnames.first() {
        Some(n) => format!("{n} ({})", primary_addr(h)),
        None => primary_addr(h).to_string(),
    }
}

/// Service name as nmap prints it: `ssl/http` for TLS-wrapped services.
fn service_name(p: &Port) -> String {
    let s = p.service.as_ref();
    let name = s.and_then(|s| s.name.as_deref()).unwrap_or("unknown");
    match s.and_then(|s| s.tunnel.as_deref()) {
        Some(t) => format!("{t}/{name}"),
        None => name.to_string(),
    }
}

/// "product version (extrainfo)", nmap's VERSION column.
fn version_text(p: &Port) -> String {
    let Some(s) = &p.service else {
        return String::new();
    };
    let mut parts: Vec<String> = [&s.product, &s.version]
        .into_iter()
        .flatten()
        .cloned()
        .collect();
    if let Some(x) = &s.extrainfo {
        parts.push(format!("({x})"));
    }
    parts.join(" ")
}

/// Unix seconds → "2026-10-09 14:03:07 UTC". No date crate needed: days to
/// civil date is Howard Hinnant's algorithm.
fn utc(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400);
    let secs = epoch.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

fn header_line(r: &ScanResult) -> String {
    let when = r.start.map(utc).unwrap_or_else(|| "an unknown time".into());
    format!(
        "# Nmap {} scan initiated {when} as: {}\n\
         # Rebuilt by Cartograph from the saved XML (not nmap's own output).\n",
        r.version, r.args
    )
}

fn done_line(r: &ScanResult) -> String {
    let (total, up, secs) = match &r.summary {
        Some(s) => (s.hosts_total, s.hosts_up, s.elapsed_secs.unwrap_or(0.0)),
        None => (
            r.hosts.len() as u32,
            r.hosts.iter().filter(|h| h.state == "up").count() as u32,
            0.0,
        ),
    };
    format!(
        "# Nmap done -- {total} IP address{} ({up} host{} up) scanned in {secs:.2} seconds\n",
        if total == 1 { "" } else { "es" },
        if up == 1 { "" } else { "s" },
    )
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn csv(r: &ScanResult) -> String {
    let mut out = String::from(
        "host,hostname,host_state,protocol,port,state,service,product,version,extrainfo\n",
    );
    for h in &r.hosts {
        let hostname = h
            .hostnames
            .first()
            .cloned()
            .or_else(|| h.identity.as_ref().and_then(|i| i.mdns_name.clone()))
            .unwrap_or_default();
        let lead = [primary_addr(h), &hostname, &h.state];
        let mut row = |cells: &[&str]| {
            let line: Vec<String> = lead.iter().chain(cells).map(|c| csv_field(c)).collect();
            out.push_str(&line.join(","));
            out.push('\n');
        };
        if h.ports.is_empty() {
            row(&["", "", "", "", "", "", ""]);
        }
        for p in &h.ports {
            let s = p.service.as_ref();
            let get = |f: fn(&crate::scan::Service) -> &Option<String>| {
                s.and_then(|s| f(s).as_deref()).unwrap_or("")
            };
            row(&[
                &p.protocol,
                &p.portid.to_string(),
                &p.state,
                get(|s| &s.name),
                get(|s| &s.product),
                get(|s| &s.version),
                get(|s| &s.extrainfo),
            ]);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Normal (-oN style)
// ---------------------------------------------------------------------------

/// NSE output the way nmap's normal output draws it:
/// `|_id: one line`, or `| id: first` … `|_last`.
fn script_block(out: &mut String, scripts: &[ScriptOutput]) {
    for s in scripts {
        let text = s.output.trim_matches('\n');
        let lines: Vec<&str> = text.lines().collect();
        match lines.as_slice() {
            [] => {
                let _ = writeln!(out, "|_{}: ", s.id);
            }
            [one] => {
                let _ = writeln!(out, "|_{}: {}", s.id, one.trim_start());
            }
            [first, rest @ .., last] => {
                let _ = writeln!(out, "| {}: {}", s.id, first.trim_start());
                for l in rest {
                    let _ = writeln!(out, "| {l}");
                }
                let _ = writeln!(out, "|_{last}");
            }
        }
    }
}

fn normal(r: &ScanResult) -> String {
    let mut out = header_line(r);
    for h in r.hosts.iter().filter(|h| h.state == "up") {
        let _ = writeln!(out, "Nmap scan report for {}", host_title(h));
        match &h.reason {
            Some(reason) => {
                let _ = writeln!(out, "Host is up ({reason}).");
            }
            None => out.push_str("Host is up.\n"),
        }
        if !h.ports.is_empty() {
            let rows: Vec<[String; 4]> = h
                .ports
                .iter()
                .map(|p| {
                    [
                        format!("{}/{}", p.portid, p.protocol),
                        p.state.clone(),
                        service_name(p),
                        version_text(p),
                    ]
                })
                .collect();
            let with_version = rows.iter().any(|r| !r[3].is_empty());
            let heads = ["PORT", "STATE", "SERVICE", "VERSION"];
            let cols = if with_version { 4 } else { 3 };
            let width = |c: usize| {
                rows.iter()
                    .map(|r| r[c].len())
                    .chain([heads[c].len()])
                    .max()
                    .unwrap_or(0)
            };
            let widths: Vec<usize> = (0..cols).map(width).collect();
            let line = |cells: [&str; 4]| {
                let mut l = String::new();
                for c in 0..cols {
                    if c + 1 == cols {
                        l.push_str(cells[c]);
                    } else {
                        let _ = write!(l, "{:<w$} ", cells[c], w = widths[c]);
                    }
                }
                l.trim_end().to_string()
            };
            let _ = writeln!(out, "{}", line(heads));
            for (row, p) in rows.iter().zip(&h.ports) {
                let _ = writeln!(out, "{}", line([&row[0], &row[1], &row[2], &row[3]]));
                script_block(&mut out, &p.scripts);
            }
        }
        if let Some(mac) = h.addresses.iter().find(|a| a.addr_type == "mac") {
            let vendor = mac.vendor.as_deref().unwrap_or("Unknown");
            let _ = writeln!(out, "MAC Address: {} ({vendor})", mac.addr);
        }
        if !h.scripts.is_empty() {
            out.push_str("\nHost script results:\n");
            script_block(&mut out, &h.scripts);
        }
        out.push('\n');
    }
    out.push_str(&done_line(r));
    out
}

// ---------------------------------------------------------------------------
// Grepable (-oG style)
// ---------------------------------------------------------------------------

/// nmap's grepable output swaps `/` (its field separator) for `|`.
fn gfield(s: &str) -> String {
    s.replace('/', "|")
}

fn grepable(r: &ScanResult) -> String {
    let mut out = header_line(r);
    for h in &r.hosts {
        let id = format!(
            "Host: {} ({})",
            primary_addr(h),
            h.hostnames.first().map(String::as_str).unwrap_or("")
        );
        let status = if h.state == "up" { "Up" } else { "Down" };
        let _ = writeln!(out, "{id}\tStatus: {status}");
        if h.ports.is_empty() {
            continue;
        }
        let ports: Vec<String> = h
            .ports
            .iter()
            .map(|p| {
                let s = p.service.as_ref();
                let name = s.and_then(|s| s.name.as_deref()).unwrap_or("");
                let name = match s.and_then(|s| s.tunnel.as_deref()) {
                    Some(t) => format!("{t}|{name}"),
                    None => name.to_string(),
                };
                format!(
                    "{}/{}/{}//{}//{}/",
                    p.portid,
                    p.state,
                    p.protocol,
                    gfield(&name),
                    gfield(&version_text(p))
                )
            })
            .collect();
        let _ = writeln!(out, "{id}\tPorts: {}", ports.join(", "));
    }
    out.push_str(&done_line(r));
    out
}

// ---------------------------------------------------------------------------
// HTML report
// ---------------------------------------------------------------------------

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            _ => o.push(c),
        }
    }
    o
}

const REPORT_CSS: &str = "\
:root{color-scheme:light dark;--bg:#f7f8fa;--card:#fff;--ink:#16202c;--muted:#5d6b7a;\
--line:#dde2e8;--open:#0b7a4b;--accent:#0e7490}\
@media (prefers-color-scheme:dark){:root{--bg:#0f141a;--card:#161d25;--ink:#e3e9ef;\
--muted:#91a0ae;--line:#26313c;--open:#3ccf8e;--accent:#38bdf8}}\
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);\
font:14px/1.5 system-ui,-apple-system,'Segoe UI',sans-serif}\
main{max-width:960px;margin:0 auto;padding:32px 16px}\
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:0}\
.muted{color:var(--muted)}code,pre{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}\
.cmd{display:block;margin:12px 0;padding:10px 12px;background:var(--card);\
border:1px solid var(--line);border-radius:8px;overflow-x:auto;white-space:pre}\
.stats{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0 24px}\
.stat{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 14px;min-width:120px}\
.stat b{display:block;font-size:20px}\
.host{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin:0 0 16px;\
break-inside:avoid}\
.host header{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:8px}\
table{width:100%;border-collapse:collapse;margin-top:8px}\
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}\
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}\
.open{color:var(--open);font-weight:600}\
pre{margin:4px 0 0;white-space:pre-wrap;color:var(--muted)}\
footer{margin-top:32px;font-size:12px}";

fn html(title: &str, r: &ScanResult) -> String {
    let up: Vec<&Host> = r.hosts.iter().filter(|h| h.state == "up").collect();
    let open = up
        .iter()
        .flat_map(|h| &h.ports)
        .filter(|p| p.state == "open")
        .count();
    let when = r.start.map(utc).unwrap_or_default();
    let mut o = String::new();
    let _ = write!(
        o,
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>Scan report: {t}</title><style>{REPORT_CSS}</style></head><body><main>\
         <h1>Scan report: {t}</h1><div class=\"muted\">{when} · {scanner} {ver}</div>\
         <code class=\"cmd\">{args}</code><div class=\"stats\">\
         <div class=\"stat\"><b>{up}</b>host{ups} up</div>\
         <div class=\"stat\"><b>{open}</b>open port{opens}</div>",
        t = esc(title),
        scanner = esc(&r.scanner),
        ver = esc(&r.version),
        args = esc(&r.args),
        up = up.len(),
        ups = if up.len() == 1 { "" } else { "s" },
        opens = if open == 1 { "" } else { "s" },
    );
    if let Some(secs) = r.summary.as_ref().and_then(|s| s.elapsed_secs) {
        let _ = write!(o, "<div class=\"stat\"><b>{secs:.1}s</b>scan time</div>");
    }
    o.push_str("</div>");
    if up.is_empty() {
        o.push_str("<p class=\"muted\">No hosts were up.</p>");
    }
    for h in up {
        let mut also: Vec<String> = h
            .addresses
            .iter()
            .filter(|a| a.addr != primary_addr(h))
            .map(|a| match &a.vendor {
                Some(v) => format!("{} ({v})", a.addr),
                None => a.addr.clone(),
            })
            .collect();
        if let Some(n) = h.identity.as_ref().and_then(|i| i.mdns_name.as_ref()) {
            also.push(n.clone());
        }
        let _ = write!(
            o,
            "<section class=\"host\"><header><h2>{}</h2><span class=\"muted\">{}</span></header>",
            esc(&host_title(h)),
            esc(&also.join(" · "))
        );
        if h.ports.is_empty() {
            o.push_str("<div class=\"muted\">No ports reported.</div>");
        } else {
            o.push_str(
                "<table><thead><tr><th>Port</th><th>State</th><th>Service</th>\
                 <th>Version</th></tr></thead><tbody>",
            );
            for p in &h.ports {
                let _ = write!(
                    o,
                    "<tr><td>{}/{}</td><td{}>{}</td><td>{}</td><td>{}",
                    p.portid,
                    esc(&p.protocol),
                    if p.state == "open" {
                        " class=\"open\""
                    } else {
                        ""
                    },
                    esc(&p.state),
                    esc(&service_name(p)),
                    esc(&version_text(p)),
                );
                for s in &p.scripts {
                    let _ = write!(o, "<pre>{}: {}</pre>", esc(&s.id), esc(s.output.trim()));
                }
                o.push_str("</td></tr>");
            }
            o.push_str("</tbody></table>");
        }
        for s in &h.scripts {
            let _ = write!(o, "<pre>{}: {}</pre>", esc(&s.id), esc(s.output.trim()));
        }
        o.push_str("</section>");
    }
    o.push_str(
        "<footer class=\"muted\">Generated by Cartograph from nmap's XML output.</footer>\
         </main></body></html>\n",
    );
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::parse_nmap_xml;

    const MULTI: &str = include_str!("../tests/fixtures/multi-host-version.xml");
    const SCRIPTS: &str = include_str!("../tests/fixtures/localhost-scripts.xml");

    fn parsed(xml: &str) -> ScanResult {
        parse_nmap_xml(xml).unwrap()
    }

    #[test]
    fn xml_is_the_stored_bytes() {
        assert_eq!(render(Format::Xml, "t", &parsed(MULTI), MULTI), MULTI);
    }

    #[test]
    fn json_round_trips_the_model() {
        let r = parsed(MULTI);
        let v: serde_json::Value =
            serde_json::from_str(&render(Format::Json, "t", &r, MULTI)).unwrap();
        assert_eq!(v["hosts"].as_array().unwrap().len(), r.hosts.len());
        assert_eq!(v["args"], r.args);
    }

    #[test]
    fn csv_has_a_row_per_port_and_quotes_fields() {
        let r = parsed(MULTI);
        let out = csv(&r);
        let ports: usize = r.hosts.iter().map(|h| h.ports.len().max(1)).sum();
        assert_eq!(out.lines().count(), 1 + ports);
        assert!(out.starts_with("host,hostname,host_state,protocol,port,"));
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("plain"), "plain");
    }

    #[test]
    fn normal_output_looks_like_nmaps() {
        let r = parsed(MULTI);
        let out = normal(&r);
        assert!(out.starts_with("# Nmap "), "{out}");
        assert!(out.contains("Nmap scan report for "), "{out}");
        assert!(out.contains("PORT "), "{out}");
        assert!(out.contains("22/tcp"), "{out}");
        assert!(out.trim_end().ends_with("seconds"), "{out}");
        // Down hosts aren't reported, as in nmap's default output.
        let up = r.hosts.iter().filter(|h| h.state == "up").count();
        assert_eq!(out.matches("Nmap scan report for").count(), up);
    }

    #[test]
    fn normal_output_draws_script_blocks() {
        let mut out = String::new();
        script_block(
            &mut out,
            &[
                ScriptOutput {
                    id: "http-title".into(),
                    output: "Hello".into(),
                },
                ScriptOutput {
                    id: "ssl-cert".into(),
                    output: "Subject: a\nIssuer: b\nSHA-1: c".into(),
                },
            ],
        );
        assert_eq!(
            out,
            "|_http-title: Hello\n| ssl-cert: Subject: a\n| Issuer: b\n|_SHA-1: c\n"
        );
        // A real scan with scripts renders them under their port.
        assert!(normal(&parsed(SCRIPTS)).contains("|"));
    }

    #[test]
    fn grepable_has_status_and_ports_lines() {
        let r = parsed(MULTI);
        let out = grepable(&r);
        assert_eq!(out.matches("\tStatus: ").count(), r.hosts.len());
        assert!(out.contains("\tStatus: Down"), "{out}");
        let ports_line = out.lines().find(|l| l.contains("\tPorts: ")).unwrap();
        assert!(ports_line.contains("22/open/tcp//ssh//"), "{ports_line}");
        assert_eq!(gfield("a/b"), "a|b");
    }

    #[test]
    fn html_report_escapes_everything_and_is_self_contained() {
        let mut r = parsed(MULTI);
        r.args = "nmap <script>alert(1)</script>".into();
        let out = html("<b>t</b>", &r);
        assert!(out.starts_with("<!doctype html>"));
        assert!(!out.contains("<script>"), "unescaped args");
        assert!(out.contains("&lt;script&gt;"));
        assert!(out.contains("Scan report: &lt;b&gt;t&lt;/b&gt;"));
        // No external resources: everything is inline.
        assert!(!out.contains("http://") && !out.contains("https://") && !out.contains("src="));
    }

    #[test]
    fn utc_formats_epochs() {
        assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc(1_760_011_387), "2025-10-09 12:03:07 UTC");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00:00 UTC"); // leap day
    }
}
