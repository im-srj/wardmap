pub mod commands;
pub mod db;
pub mod diff;
pub mod identify;
pub mod nse;
pub mod runner;
pub mod scan;

use std::sync::Mutex;
use tauri::Manager;

/// Builds and runs the Tauri application.
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            // Store the database in the OS app-data dir (keyed by the bundle
            // identifier), so scans persist across restarts.
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            let conn = db::open(dir.join("cartograph.sqlite3"))?;
            app.manage(db::Db(Mutex::new(conn)));
            app.manage(runner::Runs::default());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::run_nmap_scan,
            commands::cancel_scan,
            commands::nmap_version,
            commands::list_scans,
            commands::get_scan,
            commands::diff_scans,
            commands::list_nse_scripts,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| {
            // Don't leave nmap processes running after the window closes.
            if let tauri::RunEvent::Exit = event {
                app.state::<runner::Runs>().kill_all();
            }
        });
}
