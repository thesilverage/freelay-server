//! Server-wide failure guard, not a per-user storage allocation.
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

pub struct WriteGuard {
    paths: Mutex<Vec<PathBuf>>,
    minimum_free_bytes: u64,
    configured_read_only: bool,
    pub read_only: Arc<AtomicBool>,
}

impl WriteGuard {
    pub fn new(paths: Vec<PathBuf>, minimum_free_bytes: u64, configured_read_only: bool) -> Self {
        let guard = Self {
            paths: Mutex::new(paths),
            minimum_free_bytes,
            configured_read_only,
            read_only: Arc::new(AtomicBool::new(true)),
        };
        guard.refresh();
        guard
    }
    pub fn add_path(&self, path: PathBuf) {
        self.paths
            .lock()
            .expect("write guard lock poisoned")
            .push(path);
        self.refresh();
    }
    pub fn refresh(&self) -> bool {
        let blocked = self.configured_read_only
            || self
                .paths
                .lock()
                .map(|paths| {
                    paths.iter().any(|path| {
                        fs2::available_space(path)
                            .map(|free| free < self.minimum_free_bytes)
                            .unwrap_or(true)
                    })
                })
                .unwrap_or(true);
        let previous = self.read_only.swap(blocked, Ordering::AcqRel);
        !previous && blocked
    }
    pub fn writable(&self) -> bool {
        !self.read_only.load(Ordering::Acquire)
    }
}
