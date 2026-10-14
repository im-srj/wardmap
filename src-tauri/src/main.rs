// Thin binary entry point. All app logic lives in the library crate
// (wardmap_lib) so it can be shared with tests and example harnesses.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    wardmap_lib::run();
}
