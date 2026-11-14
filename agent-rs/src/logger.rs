//! Журнал агента: C:\ProgramData\DeepSec\agent.log, 5 МБ × 3 файла (как RotatingFileHandler у Python-агента).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

const MAX_BYTES: u64 = 5_000_000;
const BACKUPS: usize = 3;

struct FileLogger {
    path: PathBuf,
    file: Mutex<Option<File>>,
    console: bool,
}

impl FileLogger {
    fn rotate(&self, file: &mut Option<File>) {
        *file = None;
        for i in (1..BACKUPS).rev() {
            let _ = std::fs::rename(self.path.with_extension(format!("log.{i}")), self.path.with_extension(format!("log.{}", i + 1)));
        }
        let _ = std::fs::rename(&self.path, self.path.with_extension("log.1"));
    }
}

impl log::Log for FileLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Info && metadata.target().starts_with("DeepSecAgent")
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let module = record.module_path().unwrap_or("").replace("DeepSecAgent::", "deepsec.");
        let line = format!("{} {} {}: {}\n", chrono::Local::now().format("%Y-%m-%d %H:%M:%S,%3f"), record.level(), module, record.args());
        if self.console {
            eprint!("{line}");
        }
        let mut guard = self.file.lock().unwrap();
        if guard.as_ref().and_then(|f| f.metadata().ok()).is_some_and(|m| m.len() > MAX_BYTES) {
            self.rotate(&mut guard);
        }
        if guard.is_none() {
            *guard = OpenOptions::new().create(true).append(true).open(&self.path).ok();
        }
        if let Some(file) = guard.as_mut() {
            let _ = file.write_all(line.as_bytes());
        }
    }

    fn flush(&self) {}
}

pub fn init(path: PathBuf, console: bool) {
    let logger = FileLogger { path, file: Mutex::new(None), console };
    if log::set_boxed_logger(Box::new(logger)).is_ok() {
        log::set_max_level(log::LevelFilter::Info);
    }
}
