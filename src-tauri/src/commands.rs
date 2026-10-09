//! Tauri commands exposed to the frontend. These are the only DB-aware layer;
//! `scan` and `db` stay free of Tauri types.

use tauri::State;

use crate::db::{self, Db, StoredScan};
use crate::diff::{self, ScanDiff};
use crate::identify;
use crate::nse::{self, NseScript};
use crate::scan::{self, ScanResult};

/// Run a scan, persist it, and return the parsed result.
#[tauri::command]
pub fn run_nmap_scan(
    target: String,
    flags: Vec<String>,
    db: State<Db>,
) -> Result<ScanResult, String> {
    // Capture the raw XML so we can both parse it now and store it verbatim.
    let xml = scan::run_nmap_raw(&target, &flags).map_err(|e| e.to_string())?;
    let mut result = scan::parse_nmap_xml(&xml).map_err(|e| e.to_string())?;

    // Name/MAC identification for LAN hosts the scan found up (~1.5s of mDNS
    // listening when there are any). Done before taking the DB lock.
    let ids = identify::identify(&identify::up_ipv4s(&result));
    identify::attach(&mut result, &ids);

    let conn =
        db.0.lock()
            .map_err(|_| "database lock poisoned".to_string())?;
    let scan_id = db::insert_scan(&conn, &target, &result, &xml).map_err(|e| e.to_string())?;
    db::insert_identities(&conn, scan_id, &ids).map_err(|e| e.to_string())?;

    Ok(result)
}

/// List saved scans, newest first, for the history panel.
#[tauri::command]
pub fn list_scans(db: State<Db>) -> Result<Vec<StoredScan>, String> {
    let conn =
        db.0.lock()
            .map_err(|_| "database lock poisoned".to_string())?;
    db::list_scans(&conn).map_err(|e| e.to_string())
}

/// Re-materialize a saved scan by re-parsing its stored XML.
#[tauri::command]
pub fn get_scan(id: i64, db: State<Db>) -> Result<ScanResult, String> {
    let conn =
        db.0.lock()
            .map_err(|_| "database lock poisoned".to_string())?;
    let xml = db::get_scan_xml(&conn, id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("scan {id} not found"))?;
    let mut result = scan::parse_nmap_xml(&xml).map_err(|e| e.to_string())?;
    let ids = db::get_identities(&conn, id).map_err(|e| e.to_string())?;
    identify::attach(&mut result, &ids);
    Ok(result)
}

/// Diff two saved scans (old vs new), each re-parsed from its stored XML.
#[tauri::command]
pub fn diff_scans(old_id: i64, new_id: i64, db: State<Db>) -> Result<ScanDiff, String> {
    let conn =
        db.0.lock()
            .map_err(|_| "database lock poisoned".to_string())?;
    let load = |id: i64| -> Result<ScanResult, String> {
        let xml = db::get_scan_xml(&conn, id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("scan {id} not found"))?;
        scan::parse_nmap_xml(&xml).map_err(|e| e.to_string())
    };
    let old = load(old_id)?;
    let new = load(new_id)?;
    Ok(diff::diff_scans(&old, &new))
}

/// The installed nmap's NSE script catalogue, for the script browser.
#[tauri::command]
pub fn list_nse_scripts() -> Result<Vec<NseScript>, String> {
    nse::list_scripts().map_err(|e| e.to_string())
}
