//! Tauri commands exposed to the frontend. These are the only DB-aware layer;
//! `scan` and `db` stay free of Tauri types.

use tauri::State;

use crate::db::{self, Db, StoredScan};
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
    let result = scan::parse_nmap_xml(&xml).map_err(|e| e.to_string())?;

    let conn =
        db.0.lock()
            .map_err(|_| "database lock poisoned".to_string())?;
    db::insert_scan(&conn, &target, &result, &xml).map_err(|e| e.to_string())?;

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
    scan::parse_nmap_xml(&xml).map_err(|e| e.to_string())
}
