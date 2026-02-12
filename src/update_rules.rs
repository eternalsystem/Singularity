use crate::log;
use crate::signature_engine::SignatureEngine;
use regex::Regex;
use std::io::Cursor;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use walkdir::WalkDir;

const UPDATE_INTERVAL: Duration = Duration::from_secs(20 * 60); // 20 minutes
const RULES_URL: &str =
    "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip";

pub struct RulesUpdater {
    engine: SignatureEngine,
    rules_dir: PathBuf,
}

impl RulesUpdater {
    pub fn new(engine: SignatureEngine, rules_dir: PathBuf) -> Self {
        Self { engine, rules_dir }
    }

    pub fn start_background_loop(self) {
        thread::spawn(move || {
            // Initial check/download
            log::log_info("Starting YARA rules update check...");
            if let Err(e) = self.update_rules() {
                log::log_error(&format!("Failed to update rules: {}", e));
            }

            loop {
                thread::sleep(UPDATE_INTERVAL);
                log::log_info("Checking for YARA rule updates...");
                if let Err(e) = self.update_rules() {
                    log::log_error(&format!("Failed to update rules: {}", e));
                }
            }
        });
    }

    fn sanitize_rules(&self, dir: &std::path::Path) -> anyhow::Result<()> {
        log::log_info("Sanitizing rules...");

        // 1. Check if 'packages' directory exists.
        // If it exists, we prefer the individual files inside it (or the packages), so we should remove/disable the root monolithic .yar files
        // to avoid duplicates.
        let packages_path = dir.join("packages");
        let has_packages = packages_path.exists();

        if has_packages {
            log::log_info(
                "Found 'packages' directory, cleaning up root monolithic files to avoid duplicates...",
            );
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    if let Some(ext) = path.extension() {
                        if ext == "yar" || ext == "yara" {
                            log::log_info(&format!(
                                "Removing root rule file: {:?}",
                                path.file_name().unwrap_or_default()
                            ));
                            let _ = std::fs::remove_file(path);
                        }
                    }
                }
            }
        }

        // 2. Process all rule files (recursively)
        for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "yar" || ext == "yara" {
                        if let Err(e) = self.clean_rule_file(path) {
                            log::log_warning(&format!(
                                "Failed to clean rule file {:?}: {}",
                                path, e
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn clean_rule_file(&self, path: &std::path::Path) -> anyhow::Result<()> {
        let content = std::fs::read_to_string(path)?;

        // Fast check
        let has_unsupported_sigs =
            content.contains("pe.signatures") || content.contains("pe.number_of_signatures");
        let has_unsupported_imports = content.contains("import \"cuckoo\"")
            || content.contains("import \"magic\"")
            || content.contains("import \"console\"")
            || content.contains("import \"dotnet\"")
            || content.contains("import \"androguard\"");

        if !has_unsupported_sigs && !has_unsupported_imports {
            return Ok(());
        }

        log::log_info(&format!(
            "Cleaning unsupported features from {:?}",
            path.file_name().unwrap_or_default()
        ));

        // Regex to find rule starts.
        // Matches "rule Name", "private rule Name", "global rule Name" at start of line.
        let rule_pattern = Regex::new(r"(?m)^(?:private\s+|global\s+)?rule\s+([A-Za-z0-9_]+)")?;

        let mut new_content = String::with_capacity(content.len());
        let mut removed_rules = std::collections::HashSet::new();

        let matches: Vec<_> = rule_pattern.find_iter(&content).collect();

        if matches.is_empty() {
            // Just filter imports if no rules found (unlikely)
            let filtered = self.filter_imports(&content);
            std::fs::write(path, filtered)?;
            return Ok(());
        }

        // Handle header (imports, includes)
        let first_rule_start = matches[0].start();
        new_content.push_str(&self.filter_imports(&content[..first_rule_start]));

        // Process rules
        let mut kept_count = 0;
        let mut removed_count = 0;

        for i in 0..matches.len() {
            let start = matches[i].start();
            let end = if i + 1 < matches.len() {
                matches[i + 1].start()
            } else {
                content.len()
            };

            let rule_text = &content[start..end];

            // Extract rule name from capture group 1
            // We need to run captures on the small substring match, or just parse it.
            // The match itself is "rule Name" or "private rule Name"
            let match_str = matches[i].as_str();
            // Split by whitespace and take the last part
            let rule_name = match_str.split_whitespace().last().unwrap_or("unknown");

            let mut is_bad = rule_text.contains("pe.signatures")
                || rule_text.contains("pe.number_of_signatures")
                || rule_text.contains("dotnet.")
                || rule_text.contains("androguard.")
                || rule_text.contains("console.")
                || rule_text.contains("cuckoo.")
                || rule_text.contains("magic.");

            if !is_bad {
                for removed in &removed_rules {
                    // Check if this rule references a removed rule.
                    // A reference is usually the identifier itself.
                    // To be safe, check if the identifier exists as a word.
                    // But simpler: contains(removed)
                    if rule_text.contains(removed) {
                        is_bad = true;
                        break;
                    }
                }
            }

            if !is_bad {
                new_content.push_str(rule_text);
                kept_count += 1;
            } else {
                removed_rules.insert(rule_name.to_string());
                removed_count += 1;
            }
        }

        log::log_info(&format!(
            "Sanitized {:?}: kept {} rules, removed {} rules.",
            path.file_name().unwrap_or_default(),
            kept_count,
            removed_count
        ));

        std::fs::write(path, new_content)?;
        Ok(())
    }

    fn filter_imports(&self, text: &str) -> String {
        let mut res = String::new();
        for line in text.lines() {
            if line.trim().starts_with("import") {
                if line.contains("\"cuckoo\"")
                    || line.contains("\"magic\"")
                    || line.contains("\"console\"")
                    || line.contains("\"dotnet\"")
                    || line.contains("\"androguard\"")
                {
                    continue;
                }
            }
            res.push_str(line);
            res.push('\n');
        }
        res
    }

    fn update_rules(&self) -> anyhow::Result<()> {
        if !self.rules_dir.exists() {
            std::fs::create_dir_all(&self.rules_dir)?;
        }

        // Check if we already have rules?
        // For now, let's always try to download if we are in this loop.
        // The user can opt-out via the App consent which prevents this loop from starting.

        let client = reqwest::blocking::Client::new();
        log::log_info(&format!("Downloading YARA rules from {}", RULES_URL));

        let response = client.get(RULES_URL).send()?;
        if !response.status().is_success() {
            anyhow::bail!("Failed to download rules: {}", response.status());
        }

        let bytes = response.bytes()?;
        let reader = Cursor::new(bytes);
        let mut archive = zip::ZipArchive::new(reader)?;

        // Extract everything to rules_dir
        archive.extract(&self.rules_dir)?;

        self.sanitize_rules(&self.rules_dir)?;

        log::log_info("Rules extracted, reloading engine...");
        match self.engine.load_rules(&self.rules_dir) {
            Ok(count) => log::log_info(&format!("Loaded rules from {} files.", count)),
            Err(e) => log::log_error(&format!("Error reloading rules: {}", e)),
        }

        Ok(())
    }
}
