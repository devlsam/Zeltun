use std::collections::VecDeque;
use std::ffi::{c_char, CString};
use std::sync::{Mutex, OnceLock};

pub type ZeltunLogCallback = extern "C" fn(level: u8, msg: *const c_char);

pub const LOG_INFO: u8 = 0;
pub const LOG_WARN: u8 = 1;
pub const LOG_ERROR: u8 = 2;

const MAX_LOG_ENTRIES: usize = 256;

struct LogState {
    queue: VecDeque<(u8, String)>,
    last_error: String,
    callback: Option<ZeltunLogCallback>,
}

static LOG_STATE: OnceLock<Mutex<LogState>> = OnceLock::new();

fn state() -> &'static Mutex<LogState> {
    LOG_STATE.get_or_init(|| {
        Mutex::new(LogState {
            queue: VecDeque::with_capacity(64),
            last_error: String::new(),
            callback: None,
        })
    })
}

/// Records a structured engine log entry into the bounded ring buffer and optional C callback.
pub fn push_log(level: u8, msg: impl Into<String>) {
    let text = msg.into();
    match level {
        LOG_ERROR => eprintln!("[ZELTUN ERR] {}", text),
        _ => println!("[ZELTUN] {}", text),
    }

    let cb = {
        let mut guard = state().lock().unwrap();
        if level == LOG_ERROR {
            guard.last_error = text.clone();
        }
        if guard.queue.len() >= MAX_LOG_ENTRIES {
            guard.queue.pop_front();
        }
        guard.queue.push_back((level, text.clone()));
        guard.callback
    };

    if let Some(func) = cb {
        if let Ok(cstr) = CString::new(text) {
            func(level, cstr.as_ptr());
        }
    }
}

/// Records an error message both as a log entry and as the current last error.
pub fn set_last_error(msg: impl Into<String>) -> String {
    let s = msg.into();
    push_log(LOG_ERROR, s.clone());
    s
}

/// Clears any stored last error message (called on clean start).
pub fn clear_last_error() {
    if let Ok(mut guard) = state().lock() {
        guard.last_error.clear();
    }
}

/// Pops the oldest buffered log entry for non-blocking host polling.
pub fn poll_log_entry() -> Option<(u8, String)> {
    state().lock().ok()?.queue.pop_front()
}

/// Returns the most recent engine error message.
pub fn get_last_error_str() -> String {
    state()
        .lock()
        .map(|g| g.last_error.clone())
        .unwrap_or_default()
}

/// Installs or clears an optional C-ABI log callback.
pub fn set_log_callback(cb: Option<ZeltunLogCallback>) {
    if let Ok(mut guard) = state().lock() {
        guard.callback = cb;
    }
}

