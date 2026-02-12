use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;

lazy_static::lazy_static! {
    static ref LOG_FILE: Mutex<Option<std::fs::File>> = Mutex::new(None);
}

pub fn init() {
    let _ = std::fs::remove_file("debug.log"); // Clear previous log
    if let Ok(file) = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open("debug.log")
    {
        *LOG_FILE.lock().unwrap() = Some(file);
    }
}

pub fn write(msg: &str) {
    // Also print to stdout for terminal users
    println!("{}", msg);

    // Write to file
    if let Ok(mut guard) = LOG_FILE.lock() {
        if let Some(file) = guard.as_mut() {
            let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
            let _ = writeln!(file, "[{}] {}", timestamp, msg);
        }
    }
}

// Macro to make usage easier
#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        $crate::log::write(&format!($($arg)*));
    }
}

pub fn log_info(msg: &str) {
    write(&format!("[INFO] {}", msg));
}

pub fn log_error(msg: &str) {
    write(&format!("[ERROR] {}", msg));
}

pub fn log_warning(msg: &str) {
    write(&format!("[WARN] {}", msg));
}
