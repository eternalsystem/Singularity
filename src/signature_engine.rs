use anyhow::Result;
use boreal::Compiler;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::log;

#[derive(Clone)]
pub struct SignatureEngine {
    scanner: Arc<Mutex<Option<boreal::Scanner>>>,
}

impl Default for SignatureEngine {
    fn default() -> Self {
        Self {
            scanner: Arc::new(Mutex::new(None)),
        }
    }
}

impl SignatureEngine {
    pub fn load_rules(&self, rules_dir: &Path) -> Result<usize> {
        let mut compiler = Compiler::new();
        let mut file_count = 0;

        if !rules_dir.exists() {
            std::fs::create_dir_all(rules_dir)?;
        }

        for entry in walkdir::WalkDir::new(rules_dir) {
            let entry = entry?;
            if entry
                .path()
                .extension()
                .map_or(false, |e| e == "yar" || e == "yara")
            {
                if let Err(err) = compiler.add_rules_file(entry.path()) {
                    log::log_error(&format!(
                        "Failed to compile rule file {:?}: {:?}",
                        entry.path(),
                        err
                    ));
                } else {
                    file_count += 1;
                }
            }
        }

        let scanner = compiler.into_scanner();
        *self.scanner.lock().unwrap() = Some(scanner);

        Ok(file_count)
    }

    pub fn scan_bytes(&self, data: &[u8]) -> Vec<String> {
        let guard = self.scanner.lock().unwrap();
        if let Some(scanner) = &*guard {
            if let Ok(res) = scanner.scan_mem(data) {
                return res
                    .matched_rules
                    .iter()
                    .map(|r| r.name.to_string())
                    .collect();
            }
        }
        Vec::new()
    }
}
