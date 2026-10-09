//! Temporary harness: `cargo run --example identify_demo -- 192.168.1.148 …`
//! prints what Cartograph's post-scan identification finds for each address.
use std::net::Ipv4Addr;

fn main() {
    let ips: Vec<Ipv4Addr> = std::env::args()
        .skip(1)
        .filter_map(|a| a.parse().ok())
        .collect();
    let start = std::time::Instant::now();
    let ids = cartograph_lib::identify::identify(&ips);
    for ip in &ips {
        println!("{ip:<15} {:?}", ids.get(ip));
    }
    eprintln!("took {:?}", start.elapsed());
}
