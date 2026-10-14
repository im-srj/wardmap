//! Temporary CLI harness for M1 — proves `run_scan` works end-to-end against a
//! real nmap binary. Not part of the app; run it by hand:
//!
//!   cargo run --example scan_demo -- localhost
//!   cargo run --example scan_demo -- 127.0.0.1 -F
//!
//! First arg is the target; any remaining args are passed to nmap as flags.
//! This will be superseded by the UI in M2.

use wardmap_lib::scan::run_scan;

fn main() {
    let mut args = std::env::args().skip(1);
    let target = args.next().unwrap_or_else(|| {
        eprintln!("usage: scan_demo <target> [nmap flags...]");
        std::process::exit(2);
    });
    let flags: Vec<String> = args.collect();

    eprintln!("scanning {target:?} with flags {flags:?} ...");
    match run_scan(&target, &flags) {
        Ok(result) => {
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
            eprintln!("\nparsed {} host(s)", result.hosts.len());
            for h in &result.hosts {
                let addr = h.addresses.first().map(|a| a.addr.as_str()).unwrap_or("?");
                let open = h.ports.iter().filter(|p| p.state == "open").count();
                eprintln!("  {addr} [{}] — {open} open port(s)", h.state);
            }
        }
        Err(e) => {
            eprintln!("scan failed: {e}");
            std::process::exit(1);
        }
    }
}
