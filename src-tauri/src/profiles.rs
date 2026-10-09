//! Reading Zenmap's saved profiles (`~/.zenmap/scan_profile.usp`), so people
//! moving from Zenmap keep their scan profiles.
//!
//! The file is Python `ConfigParser` INI: one `[Profile name]` section per
//! profile, with `command = nmap …` and `description = …` keys (plus some
//! Zenmap-only keys we ignore). Values may continue on indented lines.

use crate::cmdline;

#[derive(Debug, Clone, PartialEq)]
pub struct ZenmapProfile {
    pub name: String,
    /// Options only (see [`cmdline::options_only`]): targets are dropped.
    pub command: String,
    pub description: String,
}

/// Parse a Zenmap `scan_profile.usp`. Sections without a `command` key are
/// skipped; so is anything before the first section.
pub fn parse_zenmap_usp(text: &str) -> Vec<ZenmapProfile> {
    // (name, key → value) in file order.
    let mut sections: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim_end();
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        // An indented line continues the previous value.
        if line.starts_with([' ', '\t']) {
            if let Some((_, value)) = sections.last_mut().and_then(|(_, kv)| kv.last_mut()) {
                value.push(' ');
                value.push_str(trimmed);
            }
            continue;
        }
        if let Some(name) = trimmed.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            sections.push((name.trim().to_string(), Vec::new()));
            continue;
        }
        let Some((_, kv)) = sections.last_mut() else {
            continue;
        };
        if let Some(at) = trimmed.find(['=', ':']) {
            let key = trimmed[..at].trim().to_ascii_lowercase();
            let value = trimmed[at + 1..].trim().to_string();
            kv.push((key, value));
        }
    }

    sections
        .into_iter()
        .filter_map(|(name, kv)| {
            let get = |k: &str| kv.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
            let command = get("command")?;
            (!name.is_empty()).then(|| ZenmapProfile {
                name,
                command: cmdline::options_only(&command),
                description: get("description").unwrap_or_default(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Excerpt of the scan_profile.usp Zenmap 7.9x ships, plus a user profile
    // that saved a target and a wrapped description.
    const USP: &str = "\
[Intense scan]
command = nmap -T4 -A -v
description = An intense, comprehensive scan. The -A option enables OS detection (-O),
\tversion detection (-sV), script scanning (-sC), and traceroute (--traceroute).
hint =

[Ping scan]
command = nmap -sn
description = This scan only finds which targets are up and does not port scan them.

[Regular scan]
command = nmap
description = A basic port scan with no extra options.

[Slow comprehensive scan]
command = nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script \"default or (discovery and safe)\"

; a comment
[My web check]
command: nmap -p 80,443 -sV 192.168.1.10

[No command here]
description = ignored
";

    #[test]
    fn reads_zenmap_profiles() {
        let p = parse_zenmap_usp(USP);
        let names: Vec<&str> = p.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "Intense scan",
                "Ping scan",
                "Regular scan",
                "Slow comprehensive scan",
                "My web check"
            ]
        );
        assert_eq!(p[0].command, "-T4 -A -v");
        assert!(p[0].description.ends_with("and traceroute (--traceroute)."));
        assert!(p[0].description.contains("(-O), version detection"));
        assert_eq!(p[1].command, "-sn");
        assert_eq!(p[2].command, "");
        // Quoted script expression survives; target is dropped.
        assert!(
            p[3].command
                .ends_with("--script 'default or (discovery and safe)'"),
            "{}",
            p[3].command
        );
        assert_eq!(p[4].command, "-p 80,443 -sV");
        assert_eq!(p[4].description, "");
    }

    #[test]
    fn ignores_junk() {
        assert!(parse_zenmap_usp("").is_empty());
        assert!(parse_zenmap_usp("command = nmap -F\n").is_empty()); // no section
        assert!(parse_zenmap_usp("not ini at all\n[]\ncommand=nmap").is_empty());
    }
}
