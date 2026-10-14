//! Render a saved nmap XML file in one of the export formats, to compare with
//! nmap's own output:
//! `cargo run --example export_demo -- scan.xml normal|grepable|csv|json|html|xml`

use wardmap_lib::export::{self, Format};
use wardmap_lib::scan;

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(path), Some(format)) = (args.next(), args.next()) else {
        eprintln!("usage: export_demo <scan.xml> <format>");
        std::process::exit(2);
    };
    let xml = std::fs::read_to_string(&path).expect("read XML file");
    let result = scan::parse_nmap_xml(&xml).expect("parse nmap XML");
    let format: Format =
        serde_json::from_value(serde_json::Value::String(format)).expect("unknown format");
    print!("{}", export::render(format, &path, &result, &xml));
}
