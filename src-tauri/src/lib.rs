pub mod cmdline;
pub mod commands;
pub mod db;
pub mod diff;
pub mod export;
pub mod identify;
pub mod nse;
pub mod profiles;
pub mod runner;
pub mod scan;

use std::sync::Mutex;
use tauri::Manager;

/// Builds and runs the Tauri application.
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            // Store the database in the OS app-data dir (keyed by the bundle
            // identifier), so scans persist across restarts.
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            let path = dir.join("wardmap.sqlite3");
            // The app was called Cartograph (bundle id com.cartograph.app)
            // until 2026-10; carry its history over on first launch.
            if let Some(parent) = dir.parent() {
                let legacy = parent.join("com.cartograph.app").join("cartograph.sqlite3");
                if let Err(e) = db::adopt_legacy(&legacy, &path) {
                    eprintln!("couldn't move the old Cartograph database: {e}");
                }
            }
            let conn = db::open(path)?;
            app.manage(db::Db(Mutex::new(conn)));
            app.manage(runner::Runs::default());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::run_nmap_scan,
            commands::cancel_scan,
            commands::analyze_command,
            commands::nmap_version,
            commands::list_scans,
            commands::get_scan,
            commands::diff_scans,
            commands::list_nse_scripts,
            commands::list_profiles,
            commands::save_profile,
            commands::delete_profile,
            commands::import_scans,
            commands::import_zenmap_profiles,
            commands::export_scan,
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
