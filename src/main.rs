#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

#[cfg(windows)]
mod gui;

#[cfg(windows)]
fn main() {
    let initial_path = std::env::args_os().nth(1).map(std::path::PathBuf::from);
    gui::run(initial_path);
}

#[cfg(not(windows))]
fn main() {
    eprintln!("engage GUI is only available on Windows; use engage-cli instead");
}
