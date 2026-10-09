//! Device identification beyond what an unprivileged nmap run reports.
//!
//! - **MAC + vendor**: nmap only learns MAC addresses when it runs as root
//!   (raw ARP). But the OS neighbour (ARP) cache already holds the MAC of every
//!   LAN host the scan just talked to, so we read that, and look the vendor up
//!   in nmap's own `nmap-mac-prefixes` file (local, no download).
//! - **mDNS name**: what `avahi-resolve-address` does — a one-shot multicast
//!   DNS PTR query for `d.c.b.a.in-addr.arpa` (RFC 6762 §5.1). Sent from an
//!   ephemeral port, so responders reply by unicast straight back to us (§6.7),
//!   no root and no avahi daemon needed. Also sent directly to the host's
//!   port 5353 (§5.5), which covers machines with several interfaces where the
//!   default multicast route points at the wrong one (e.g. docker bridges).
//!
//! This is name resolution, not scanning: it only ever touches hosts the
//! user's own scan found up, and only private / link-local IPv4 addresses
//! (ARP and mDNS are link-local by nature anyway).

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::Serialize;
use simple_dns::rdata::RData;
use simple_dns::{Name, Packet, Question, CLASS, TYPE};

use crate::scan::ScanResult;

/// Extra identity for one host, merged into `Host.identity`.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostIdentity {
    /// Reverse mDNS name, e.g. `Pixel-7.local`.
    pub mdns_name: Option<String>,
    /// MAC from the OS ARP cache, `AA:BB:CC:DD:EE:FF`.
    pub mac: Option<String>,
    /// Vendor for `mac`, from nmap-mac-prefixes.
    pub vendor: Option<String>,
    /// Locally-administered MAC — phones/laptops use these for Wi-Fi privacy,
    /// so the vendor can't be known, but the randomness is itself a hint.
    pub mac_randomized: bool,
}

impl HostIdentity {
    fn is_empty(&self) -> bool {
        self.mdns_name.is_none() && self.mac.is_none()
    }
}

/// Upper bound on hosts we'll query, so a huge range can't turn into a flood.
const MAX_HOSTS: usize = 1024;
const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

/// Only LAN-local addresses are worth (and appropriate) asking about.
pub fn is_eligible(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_link_local()
}

/// Identify the given hosts. Never fails: any source that's unavailable
/// (no ARP access, no vendor file, no mDNS answers) just contributes nothing.
pub fn identify(hosts: &[Ipv4Addr]) -> HashMap<Ipv4Addr, HostIdentity> {
    let targets: Vec<Ipv4Addr> = hosts
        .iter()
        .copied()
        .filter(|ip| is_eligible(*ip))
        .take(MAX_HOSTS)
        .collect();
    if targets.is_empty() {
        return HashMap::new();
    }

    let arp = read_arp_cache();
    let vendors = MacVendors::load_installed();
    let names = mdns_reverse_lookup(&targets, Duration::from_millis(1500));

    let mut out = HashMap::new();
    for ip in targets {
        let mac = arp.get(&ip).cloned();
        let id = HostIdentity {
            mdns_name: names.get(&ip).cloned(),
            vendor: mac.as_deref().and_then(|m| vendors.as_ref()?.lookup(m)),
            mac_randomized: mac.as_deref().is_some_and(is_randomized_mac),
            mac,
        };
        if !id.is_empty() {
            out.insert(ip, id);
        }
    }
    out
}

/// IPv4 addresses of every host that was up.
pub fn up_ipv4s(result: &ScanResult) -> Vec<Ipv4Addr> {
    result
        .hosts
        .iter()
        .filter(|h| h.state == "up")
        .flat_map(|h| &h.addresses)
        .filter(|a| a.addr_type == "ipv4")
        .filter_map(|a| a.addr.parse().ok())
        .collect()
}

/// Copy identities onto the matching hosts (by IPv4 address).
pub fn attach(result: &mut ScanResult, ids: &HashMap<Ipv4Addr, HostIdentity>) {
    for host in &mut result.hosts {
        host.identity = host
            .addresses
            .iter()
            .filter(|a| a.addr_type == "ipv4")
            .find_map(|a| ids.get(&a.addr.parse().ok()?))
            .cloned();
    }
}

// --- ARP cache ---------------------------------------------------------------

/// Normalize `0:1a:2B:3:4:5` / `00-1A-2B-03-04-05` to `00:1A:2B:03:04:05`.
/// Returns None for anything that isn't a usable unicast MAC.
pub fn normalize_mac(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.split([':', '-']).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut bytes = [0u8; 6];
    for (b, p) in bytes.iter_mut().zip(&parts) {
        if p.is_empty() || p.len() > 2 {
            return None;
        }
        *b = u8::from_str_radix(p, 16).ok()?;
    }
    // All-zero = incomplete entry; odd first octet = multicast/broadcast.
    if bytes == [0; 6] || bytes[0] & 1 == 1 {
        return None;
    }
    Some(
        bytes
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Linux `/proc/net/arp`:
/// `IP address  HW type  Flags  HW address  Mask  Device`
pub fn parse_proc_net_arp(text: &str) -> HashMap<Ipv4Addr, String> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            let ip = cols.first()?.parse().ok()?;
            // Flags 0x0 = incomplete (no reply yet).
            if *cols.get(2)? == "0x0" {
                return None;
            }
            Some((ip, normalize_mac(cols.get(3)?)?))
        })
        .collect()
}

/// `arp -a` output on macOS (`? (192.168.1.1) at c8:b3:73:a:b:c on en0 …`)
/// and Windows (`  192.168.1.1   c8-b3-73-0a-0b-0c   dynamic`).
pub fn parse_arp_a(text: &str) -> HashMap<Ipv4Addr, String> {
    text.lines()
        .filter_map(|line| {
            let tokens = line.split_whitespace();
            let mut ip = None;
            let mut mac = None;
            for t in tokens {
                let t = t.trim_matches(|c| c == '(' || c == ')');
                if ip.is_none() {
                    ip = t.parse::<Ipv4Addr>().ok();
                } else if mac.is_none() {
                    mac = normalize_mac(t);
                }
            }
            Some((ip?, mac?))
        })
        .collect()
}

fn read_arp_cache() -> HashMap<Ipv4Addr, String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/net/arp")
            .map(|t| parse_proc_net_arp(&t))
            .unwrap_or_default()
    }
    #[cfg(not(target_os = "linux"))]
    {
        // -n: numeric only, so we don't trigger a reverse-DNS lookup per entry.
        let args: &[&str] = if cfg!(windows) { &["-a"] } else { &["-an"] };
        std::process::Command::new("arp")
            .args(args)
            .output()
            .ok()
            .map(|o| parse_arp_a(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or_default()
    }
}

// --- MAC vendors -------------------------------------------------------------

/// Locally-administered bit set (second-lowest bit of the first octet).
pub fn is_randomized_mac(mac: &str) -> bool {
    mac.get(0..2)
        .and_then(|h| u8::from_str_radix(h, 16).ok())
        .is_some_and(|b| b & 0b10 != 0)
}

/// nmap-mac-prefixes: `<hex prefix> <vendor>`; prefixes are 6, 7 or 9 hex
/// digits (IEEE MA-L / MA-M / MA-S blocks). Longest match wins.
pub struct MacVendors(HashMap<String, String>);

impl MacVendors {
    pub fn parse(text: &str) -> Self {
        Self(
            text.lines()
                .filter(|l| !l.starts_with('#'))
                .filter_map(|l| {
                    let (prefix, vendor) = l.split_once(' ')?;
                    let ok = matches!(prefix.len(), 6 | 7 | 9)
                        && prefix.chars().all(|c| c.is_ascii_hexdigit());
                    ok.then(|| (prefix.to_ascii_uppercase(), vendor.trim().to_string()))
                })
                .collect(),
        )
    }

    pub fn lookup(&self, mac: &str) -> Option<String> {
        let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        let hex = hex.to_ascii_uppercase();
        [9, 7, 6]
            .iter()
            .find_map(|&n| self.0.get(hex.get(..n)?))
            .cloned()
    }

    /// Load the vendor table shipped with the installed nmap, if we can find it.
    fn load_installed() -> Option<Self> {
        nmap_data_dirs()
            .into_iter()
            .map(|d| d.join("nmap-mac-prefixes"))
            .find_map(|p| std::fs::read_to_string(p).ok())
            .map(|t| Self::parse(&t))
    }
}

/// Where nmap keeps its data files, most specific first.
fn nmap_data_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(d) = std::env::var_os("NMAPDIR") {
        dirs.push(PathBuf::from(d));
    }
    // Relative to the nmap binary on PATH: <prefix>/bin/nmap → <prefix>/share/nmap
    // (Homebrew, /usr/local, …); on Windows the data sits next to nmap.exe.
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            if dir.join("nmap").is_file() || dir.join("nmap.exe").is_file() {
                if let Some(prefix) = dir.parent() {
                    dirs.push(prefix.join("share").join("nmap"));
                }
                dirs.push(dir);
            }
        }
    }
    for d in [
        "/usr/share/nmap",
        "/usr/local/share/nmap",
        "/opt/homebrew/share/nmap",
        r"C:\Program Files (x86)\Nmap",
        r"C:\Program Files\Nmap",
    ] {
        dirs.push(PathBuf::from(d));
    }
    dirs
}

// --- mDNS reverse lookup -----------------------------------------------------

/// `192.168.1.148` → `148.1.168.192.in-addr.arpa`
pub fn reverse_name(ip: Ipv4Addr) -> String {
    let [a, b, c, d] = ip.octets();
    format!("{d}.{c}.{b}.{a}.in-addr.arpa")
}

fn ip_from_reverse_name(name: &str) -> Option<Ipv4Addr> {
    let rest = name.trim_end_matches('.').strip_suffix(".in-addr.arpa")?;
    let mut octets: Vec<u8> = rest
        .split('.')
        .map(|p| p.parse().ok())
        .collect::<Option<_>>()?;
    if octets.len() != 4 {
        return None;
    }
    octets.reverse();
    Some(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
}

/// A one-shot PTR query for `ip`'s reverse name.
pub fn build_ptr_query(id: u16, ip: Ipv4Addr) -> Option<Vec<u8>> {
    let qname = reverse_name(ip);
    let mut packet = Packet::new_query(id);
    packet.questions.push(Question::new(
        Name::new(&qname).ok()?,
        TYPE::PTR.into(),
        CLASS::IN.into(),
        false,
    ));
    packet.build_bytes_vec().ok()
}

/// Extract `(ip, name)` pairs from any PTR records for reverse IPv4 names in
/// an mDNS response. Untrusted input from the LAN: malformed packets are just
/// ignored, and names are length-capped.
pub fn parse_ptr_response(data: &[u8]) -> Vec<(Ipv4Addr, String)> {
    let Ok(packet) = Packet::parse(data) else {
        return Vec::new();
    };
    packet
        .answers
        .iter()
        .chain(&packet.additional_records)
        .filter_map(|rr| {
            let RData::PTR(ptr) = &rr.rdata else {
                return None;
            };
            let ip = ip_from_reverse_name(&rr.name.to_string())?;
            let name = ptr.0.to_string();
            let name = name.trim_end_matches('.');
            (!name.is_empty() && name.len() <= 255).then(|| (ip, name.to_string()))
        })
        .collect()
}

fn mdns_reverse_lookup(ips: &[Ipv4Addr], wait: Duration) -> HashMap<Ipv4Addr, String> {
    let mut found = HashMap::new();
    let Ok(sock) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
        return found;
    };
    if sock
        .set_read_timeout(Some(Duration::from_millis(100)))
        .is_err()
    {
        return found;
    }
    let wanted: HashSet<Ipv4Addr> = ips.iter().copied().collect();

    let send_all = |pending: &[Ipv4Addr]| {
        for (i, ip) in pending.iter().enumerate() {
            let Some(q) = build_ptr_query(i as u16 + 1, *ip) else {
                continue;
            };
            // Best effort: a failed send just means no name for that host.
            let _ = sock.send_to(&q, SocketAddrV4::new(MDNS_GROUP, MDNS_PORT));
            let _ = sock.send_to(&q, SocketAddrV4::new(*ip, MDNS_PORT));
        }
    };

    send_all(ips);
    let start = Instant::now();
    let mut resent = false;
    let mut buf = [0u8; 9000];
    while start.elapsed() < wait && found.len() < wanted.len() {
        // One retry for anything still unanswered (UDP may drop the first).
        if !resent && start.elapsed() > wait / 3 {
            resent = true;
            let pending: Vec<_> = ips
                .iter()
                .copied()
                .filter(|ip| !found.contains_key(ip))
                .collect();
            send_all(&pending);
        }
        if let Ok((n, _)) = sock.recv_from(&mut buf) {
            for (ip, name) in parse_ptr_response(&buf[..n]) {
                if wanted.contains(&ip) {
                    found.entry(ip).or_insert(name);
                }
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_dns::rdata::PTR;
    use simple_dns::ResourceRecord;

    #[test]
    fn parses_proc_net_arp_skipping_incomplete() {
        let text = "IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         c8:b3:73:11:22:33     *        enp3s0
192.168.1.50     0x1         0x0         00:00:00:00:00:00     *        enp3s0
192.168.1.148    0x1         0x2         da:a1:19:00:00:01     *        enp3s0
";
        let m = parse_proc_net_arp(text);
        assert_eq!(m.len(), 2);
        assert_eq!(m[&"192.168.1.1".parse().unwrap()], "C8:B3:73:11:22:33");
        assert!(!m.contains_key(&"192.168.1.50".parse().unwrap()));
    }

    #[test]
    fn parses_macos_and_windows_arp_a() {
        let mac = "? (192.168.1.1) at c8:b3:73:a:b:c on en0 ifscope [ethernet]
? (192.168.1.9) at (incomplete) on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]";
        let m = parse_arp_a(mac);
        assert_eq!(m.len(), 1);
        assert_eq!(m[&"192.168.1.1".parse().unwrap()], "C8:B3:73:0A:0B:0C");

        let win = "Interface: 192.168.1.104 --- 0x5
  Internet Address      Physical Address      Type
  192.168.1.1           c8-b3-73-0a-0b-0c     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static";
        let w = parse_arp_a(win);
        // The interface header line has an IP but no MAC, so it's skipped.
        assert_eq!(w.len(), 1);
        assert_eq!(w[&"192.168.1.1".parse().unwrap()], "C8:B3:73:0A:0B:0C");
    }

    #[test]
    fn vendor_lookup_prefers_longest_prefix() {
        let v = MacVendors::parse(
            "# comment\nC8B373 Cisco-Linksys\n0055DA Ieee Registration Authority\n0055DA1 KoolPOS\nnot a line\n",
        );
        assert_eq!(
            v.lookup("C8:B3:73:11:22:33").as_deref(),
            Some("Cisco-Linksys")
        );
        assert_eq!(v.lookup("00:55:DA:10:00:00").as_deref(), Some("KoolPOS"));
        assert_eq!(
            v.lookup("00:55:DA:20:00:00").as_deref(),
            Some("Ieee Registration Authority")
        );
        assert_eq!(v.lookup("AA:BB:CC:00:00:00"), None);
    }

    #[test]
    fn detects_randomized_macs() {
        assert!(is_randomized_mac("DA:A1:19:00:00:01")); // 0xDA has bit 1 set
        assert!(is_randomized_mac("02:00:00:00:00:00"));
        assert!(!is_randomized_mac("C8:B3:73:11:22:33"));
    }

    #[test]
    fn only_lan_addresses_are_eligible() {
        for ip in ["192.168.1.5", "10.0.0.5", "172.16.3.4", "169.254.10.1"] {
            assert!(is_eligible(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "127.0.0.1", "45.33.32.156"] {
            assert!(!is_eligible(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn reverse_names_roundtrip() {
        let ip: Ipv4Addr = "192.168.1.148".parse().unwrap();
        assert_eq!(reverse_name(ip), "148.1.168.192.in-addr.arpa");
        assert_eq!(
            ip_from_reverse_name("148.1.168.192.in-addr.arpa."),
            Some(ip)
        );
        assert_eq!(ip_from_reverse_name("example.local"), None);
        assert_eq!(ip_from_reverse_name("1.2.in-addr.arpa"), None);
        assert_eq!(ip_from_reverse_name("300.1.168.192.in-addr.arpa"), None);
    }

    #[test]
    fn query_asks_for_the_reverse_ptr() {
        let bytes = build_ptr_query(7, "192.168.1.148".parse().unwrap()).unwrap();
        let p = Packet::parse(&bytes).unwrap();
        assert_eq!(p.id(), 7);
        assert_eq!(p.questions.len(), 1);
        assert_eq!(
            p.questions[0].qname.to_string(),
            "148.1.168.192.in-addr.arpa"
        );
    }

    #[test]
    fn parses_ptr_answers_and_ignores_garbage() {
        let rev = reverse_name("192.168.1.148".parse().unwrap());
        let mut reply = Packet::new_reply(7);
        reply.answers.push(ResourceRecord::new(
            Name::new(&rev).unwrap(),
            CLASS::IN,
            120,
            RData::PTR(PTR(Name::new("Pixel-7.local").unwrap())),
        ));
        // A PTR that isn't a reverse-IPv4 name (e.g. a DNS-SD browse) is ignored.
        reply.answers.push(ResourceRecord::new(
            Name::new("_googlecast._tcp.local").unwrap(),
            CLASS::IN,
            120,
            RData::PTR(PTR(Name::new("TV._googlecast._tcp.local").unwrap())),
        ));
        let bytes = reply.build_bytes_vec_compressed().unwrap();
        let got = parse_ptr_response(&bytes);
        assert_eq!(
            got,
            vec![(
                "192.168.1.148".parse().unwrap(),
                "Pixel-7.local".to_string()
            )]
        );

        assert!(parse_ptr_response(&[0xff; 7]).is_empty());
        assert!(parse_ptr_response(&bytes[..bytes.len() - 3]).is_empty());
    }

    #[test]
    fn attaches_identity_by_ipv4() {
        let xml = r#"<?xml version="1.0"?><nmaprun><host><status state="up"/>
            <address addr="192.168.1.148" addrtype="ipv4"/></host>
            <host><status state="up"/><address addr="192.168.1.9" addrtype="ipv4"/></host>
            </nmaprun>"#;
        let mut r = crate::scan::parse_nmap_xml(xml).unwrap();
        assert_eq!(up_ipv4s(&r).len(), 2);
        let id = HostIdentity {
            mdns_name: Some("Pixel-7.local".into()),
            ..Default::default()
        };
        let ids = HashMap::from([("192.168.1.148".parse().unwrap(), id.clone())]);
        attach(&mut r, &ids);
        assert_eq!(r.hosts[0].identity.as_ref(), Some(&id));
        assert_eq!(r.hosts[1].identity, None);
    }
}
