// Thin binary entry point. All app logic lives in the library crate
// (cartograph_lib) so it can be shared with tests and example harnesses.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    cartograph_lib::run();
}
