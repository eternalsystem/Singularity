use anyhow::{Context, Result};
use capstone::prelude::*;
use goblin::Object;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::io::Read;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{ffi::OsString, time::Duration};

use crate::asar_ripper;
use crate::deobfuscator;
use crate::disassemble;
use crate::extractor;
use crate::layered_analysis::{self, LayeredAnalysisReport};
use crate::secrets::{self, SecretMatch};
use crate::signature_engine::SignatureEngine;
use crate::tools_manager::{ToolManager, is_command_available};

#[derive(Debug, Clone, Serialize)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: Option<u64>,
    pub virtual_size: Option<u64>,
    pub file_offset: Option<u64>,
    pub file_size: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InstructionLine {
    pub address: u64,
    pub bytes_hex: String,
    pub mnemonic: String,
    pub op_str: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExternalToolOutput {
    pub tool: String,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct JsFileInfo {
    pub name: String,
    pub original: Option<String>,
    pub synchrony: Option<String>,
    pub path: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalysisResult {
    pub file_path: PathBuf,
    pub file_size: u64,
    pub file_format: String,
    pub language: String,
    pub kind: String,
    pub entry_point: Option<u64>,
    pub python_entrypoint: Option<String>,
    pub imports: Vec<String>,
    pub sections: Vec<SectionInfo>,
    pub strings: Vec<String>,
    pub disassembly: Vec<InstructionLine>,
    pub external: Vec<ExternalToolOutput>,
    pub warnings: Vec<String>,
    pub deobfuscated_files: Vec<(String, String)>,
    pub deobfuscated_file_locations: Vec<(String, String)>,
    pub js_files: Vec<JsFileInfo>,
    pub js_container: Option<String>,
    pub js_obfuscated: bool,
    pub is_stealer: bool,
    pub yara_matches: Vec<String>,
    pub secrets: Vec<SecretMatch>,
    pub confidence_score: u8,
    pub extracted_dir: Option<PathBuf>,
    pub layered_report: Option<LayeredAnalysisReport>,
}

fn npm_global_bin_dir() -> Option<PathBuf> {
    let npm_cmds: [&str; 2] = if cfg!(windows) {
        ["npm.cmd", "npm"]
    } else {
        ["npm", "npm"]
    };

    for npm_cmd in npm_cmds {
        let mut cmd = Command::new(npm_cmd);
        #[cfg(windows)]
        cmd.creation_flags(0x08000000);
        let out = cmd
            .args(["bin", "-g"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output();
        let Ok(out) = out else { continue };
        if !out.status.success() {
            continue;
        }
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if s.is_empty() {
            continue;
        }
        let p = PathBuf::from(s);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

fn synchrony_available() -> bool {
    if is_command_available("synchrony")
        || is_command_available("synchrony.cmd")
        || is_command_available("deobfuscator")
        || is_command_available("deobfuscator.cmd")
    {
        return true;
    }

    if let Some(bin_dir) = npm_global_bin_dir() {
        let candidates = if cfg!(windows) {
            [
                bin_dir.join("deobfuscator.cmd"),
                bin_dir.join("synchrony.cmd"),
                bin_dir.join("deobfuscator"),
                bin_dir.join("synchrony"),
            ]
            .to_vec()
        } else {
            [bin_dir.join("deobfuscator"), bin_dir.join("synchrony")].to_vec()
        };

        for p in candidates {
            if p.exists() {
                return true;
            }
        }
    }

    false
}

fn run_synchrony_capture(input_path: &Path) -> Result<(String, Option<PathBuf>)> {
    let expected_cleaned = cleaned_js_path(input_path);
    let started = std::time::SystemTime::now();
    let mut tools: Vec<OsString> = if cfg!(windows) {
        vec![
            OsString::from("synchrony.cmd"),
            OsString::from("deobfuscator.cmd"),
            OsString::from("synchrony"),
            OsString::from("deobfuscator"),
        ]
    } else {
        vec![OsString::from("synchrony"), OsString::from("deobfuscator")]
    };

    if let Some(bin_dir) = npm_global_bin_dir() {
        let extra = if cfg!(windows) {
            vec![
                bin_dir.join("deobfuscator.cmd"),
                bin_dir.join("synchrony.cmd"),
                bin_dir.join("deobfuscator"),
                bin_dir.join("synchrony"),
            ]
        } else {
            vec![bin_dir.join("deobfuscator"), bin_dir.join("synchrony")]
        };
        for p in extra {
            if p.exists() {
                tools.insert(0, p.into_os_string());
            }
        }
    }

    let mut last_error = String::new();
    let mut saw_not_found = false;
    let is_synchrony_log_text = |text: &str| -> bool {
        let mut total = 0usize;
        let mut running = 0usize;
        let mut transformer = 0usize;
        let mut shifted = 0usize;
        for line in text.lines().take(200) {
            let l = line.trim();
            if l.is_empty() {
                continue;
            }
            total += 1;
            if l.starts_with("Running ") {
                running += 1;
            }
            if l.contains(" transformer") {
                transformer += 1;
            }
            if l.starts_with("shifted =") {
                shifted += 1;
            }
        }
        total >= 3 && (running * 2 >= total || transformer * 2 >= total || shifted * 2 >= total)
    };

    let read_nonempty_cleaned = |p: &Path| -> Option<String> {
        let bytes = std::fs::read(p).ok()?;
        if bytes.is_empty() {
            return None;
        }
        let s = String::from_utf8_lossy(&bytes).into_owned();
        if s.trim().is_empty() || is_synchrony_log_text(&s) {
            None
        } else {
            Some(s)
        }
    };

    for tool in tools {
        let mut cmd = Command::new(&tool);
        cmd.arg("deobfuscate").arg(input_path);
        #[cfg(windows)]
        cmd.creation_flags(0x08000000);

        match cmd.output() {
            Ok(output) => {
                if output.status.success() {
                    if let Some(code) = read_nonempty_cleaned(&expected_cleaned) {
                        return Ok((code, Some(expected_cleaned)));
                    }

                    let parent = input_path
                        .parent()
                        .map(|p| p.to_path_buf())
                        .unwrap_or_else(|| PathBuf::from("."));
                    let file_name = input_path.file_name().unwrap_or_default().to_string_lossy();
                    let stem = input_path.file_stem().unwrap_or_default().to_string_lossy();
                    let ext = input_path
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("")
                        .to_ascii_lowercase();

                    let threshold = started
                        .checked_sub(Duration::from_secs(10))
                        .unwrap_or(started);

                    let is_recent = |p: &Path| -> bool {
                        std::fs::metadata(p)
                            .ok()
                            .and_then(|m| m.modified().ok())
                            .is_some_and(|t| t >= threshold)
                    };

                    let mut candidates: Vec<PathBuf> = Vec::new();
                    if !file_name.is_empty() {
                        candidates.push(parent.join(format!("{file_name}_clean")));
                        candidates.push(parent.join(format!("{file_name}_cleaned")));
                    }
                    if !ext.is_empty() {
                        candidates.push(parent.join(format!("{stem}.cleaned.{ext}")));
                        candidates.push(parent.join(format!("{stem}_cleaned.{ext}")));
                        candidates.push(parent.join(format!("{stem}.deobfuscated.{ext}")));
                        candidates.push(parent.join(format!("{stem}_deobfuscated.{ext}")));
                    }

                    for p in candidates {
                        if p.exists()
                            && is_recent(&p)
                            && let Some(code) = read_nonempty_cleaned(&p)
                        {
                            let _ = std::fs::write(&expected_cleaned, code.as_bytes());
                            return Ok((code, Some(expected_cleaned)));
                        }
                    }

                    let mut best: Option<(PathBuf, std::time::SystemTime)> = None;
                    if let Ok(rd) = std::fs::read_dir(&parent) {
                        for entry in rd.flatten() {
                            let p = entry.path();
                            if !p.is_file() || p == *input_path {
                                continue;
                            }
                            if !ext.is_empty()
                                && p.extension()
                                    .and_then(|e| e.to_str())
                                    .is_some_and(|e| e.to_ascii_lowercase() != ext)
                            {
                                continue;
                            }
                            let fname = p
                                .file_name()
                                .unwrap_or_default()
                                .to_string_lossy()
                                .to_ascii_lowercase();
                            if !fname.contains(&stem.to_ascii_lowercase())
                                || !(fname.contains("clean") || fname.contains("deobf"))
                            {
                                continue;
                            }
                            let mtime = entry.metadata().ok().and_then(|m| m.modified().ok());
                            let Some(mtime) = mtime else {
                                continue;
                            };
                            if mtime < threshold {
                                continue;
                            }
                            match &mut best {
                                Some((_, best_mtime)) if *best_mtime >= mtime => {}
                                _ => best = Some((p, mtime)),
                            }
                        }
                    }

                    if let Some((p, _)) = best
                        && let Some(code) = read_nonempty_cleaned(&p)
                    {
                        // Run additional string deobfuscation
                        // Removed as per user request (obsolete)

                        // Re-read the file as it might have been modified
                        if let Some(code) = read_nonempty_cleaned(&p) {
                            let _ = std::fs::write(&expected_cleaned, code.as_bytes());
                            return Ok((code, Some(expected_cleaned)));
                        }

                        let _ = std::fs::write(&expected_cleaned, code.as_bytes());
                        return Ok((code, Some(expected_cleaned)));
                    }

                    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
                    if !stdout.trim().is_empty() && !is_synchrony_log_text(&stdout) {
                        let _ = std::fs::write(&expected_cleaned, stdout.as_bytes());

                        // Run additional string deobfuscation
                        // Removed as per user request (obsolete)
                        if let Ok(code) = std::fs::read_to_string(&expected_cleaned) {
                            return Ok((code, Some(expected_cleaned)));
                        }

                        return Ok((stdout, Some(expected_cleaned)));
                    }

                    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
                    anyhow::bail!(
                        "synchrony succeeded but no cleaned output file was found. stdout:\n{}\nstderr:\n{}",
                        stdout.lines().take(25).collect::<Vec<_>>().join("\n"),
                        stderr.lines().take(25).collect::<Vec<_>>().join("\n")
                    );
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if stderr.contains("SyntaxError") {
                        anyhow::bail!(
                            "Synchrony failed to parse file (SyntaxError). The file might be a V8 snapshot or binary data, not source code.\nDetails: {}",
                            stderr.lines().next().unwrap_or("Unknown error")
                        );
                    }
                    last_error = format!("{} failed: {}", tool.to_string_lossy(), stderr);
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    saw_not_found = true;
                    continue;
                }
                last_error = format!("Failed to execute {}: {}", tool.to_string_lossy(), e);
            }
        }
    }

    if last_error.is_empty() {
        if saw_not_found && let Some(bin_dir) = npm_global_bin_dir() {
            anyhow::bail!(
                "Synchrony tool not found. npm global bin is: {}",
                bin_dir.display()
            )
        }
        anyhow::bail!(
            "Synchrony tool not found. Please ensure 'deobfuscator' is installed via npm (npm install -g deobfuscator) and available in PATH."
        )
    } else {
        anyhow::bail!("{}", last_error)
    }
}

fn looks_like_utf8_text(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    if data.len() < 16 {
        return false;
    }
    if data.contains(&0) {
        return false;
    }
    if std::str::from_utf8(data).is_err() {
        return false;
    }
    let mut printable = 0usize;
    for &b in data {
        if b == b'\n' || b == b'\r' || b == b'\t' || (0x20..=0x7e).contains(&b) {
            printable += 1;
        }
    }
    (printable as f32) / (data.len() as f32) >= 0.85
}

fn normalize_pkg_snapshot_path(s: String) -> String {
    let s = s.replace('/', "\\");
    let s_lc = s.to_ascii_lowercase();
    if let Some(idx) = s_lc.find("\\snapshot\\") {
        let after = &s[idx + "\\snapshot\\".len()..];
        return after.to_string();
    }
    s
}

fn carve_probable_js_snippets(payload: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0usize;

    while i < payload.len() {
        while i < payload.len()
            && !(payload[i] == b'\n'
                || payload[i] == b'\r'
                || payload[i] == b'\t'
                || (0x20..=0x7e).contains(&payload[i]))
        {
            i += 1;
        }

        let start = i;
        while i < payload.len()
            && (payload[i] == b'\n'
                || payload[i] == b'\r'
                || payload[i] == b'\t'
                || (0x20..=0x7e).contains(&payload[i]))
        {
            i += 1;
        }

        let end = i;
        if end <= start {
            continue;
        }

        let len = end - start;
        if len < 50 {
            continue;
        }

        let slice = &payload[start..end];
        let s = String::from_utf8_lossy(slice).into_owned();
        let s_lc = s.to_ascii_lowercase();

        let likely_js = s_lc.contains("function")
            || s_lc.contains("require(")
            || s_lc.contains("module.exports")
            || s_lc.contains("exports.")
            || s_lc.contains("console.")
            || s_lc.contains("=>")
            || s_lc.contains("use strict")
            || s_lc.contains("class ")
            || s_lc.contains("async ")
            || s_lc.contains("await ")
            || s_lc.contains("const ")
            || s_lc.contains("let ")
            || s_lc.contains("var ")
            || s_lc.contains("return ");

        if !likely_js {
            continue;
        }

        let trimmed = s.trim().to_string();
        if trimmed.len() < 200 {
            continue;
        }

        out.push(trimmed);
        if out.len() >= 25 {
            break;
        }
    }

    out
}

fn carve_js_keyword_windows(payload: &[u8]) -> Vec<String> {
    let needles: [&[u8]; 13] = [
        b"function",
        b"require(",
        b"module.exports",
        b"exports.",
        b"console.",
        b"use strict",
        b"class ",
        b"async ",
        b"await ",
        b"const ",
        b"let ",
        b"var ",
        b"return ",
    ];

    let mut positions = BTreeSet::new();
    for needle in needles {
        if needle.len() > payload.len() {
            continue;
        }
        for (idx, w) in payload.windows(needle.len()).enumerate() {
            if w == needle {
                positions.insert(idx);
            }
        }
    }

    let mut out = Vec::new();
    for pos in positions.into_iter().take(20) {
        let start = pos.saturating_sub(4096);
        let end = (pos + 4096).min(payload.len());
        let slice = &payload[start..end];

        let mut filtered = String::with_capacity(slice.len());
        for &b in slice {
            if b == b'\n' || b == b'\r' || b == b'\t' || (0x20..=0x7e).contains(&b) {
                filtered.push(b as char);
            } else {
                filtered.push(' ');
            }
        }

        let filtered = filtered.trim().to_string();
        if filtered.len() < 50 {
            continue;
        }

        let lower = filtered.to_ascii_lowercase();
        let has_kw = needles.iter().any(|&n| {
            if let Ok(s) = std::str::from_utf8(n) {
                lower.contains(s)
            } else {
                false
            }
        });

        if !has_kw {
            continue;
        }

        out.push(filtered);
        if out.len() >= 10 {
            break;
        }
    }

    out
}

fn json_value_bounds(s: &str, start: usize) -> Option<(usize, usize)> {
    let bytes = s.as_bytes();
    let mut i = start;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    let first = bytes[i];
    if first == b'{' || first == b'[' {
        let mut depth = 0i32;
        let mut in_str = false;
        let mut escape = false;
        let mut j = i;
        while j < bytes.len() {
            let c = bytes[j];
            if in_str {
                if escape {
                    escape = false;
                } else if c == b'\\' {
                    escape = true;
                } else if c == b'"' {
                    in_str = false;
                }
                j += 1;
                continue;
            }
            match c {
                b'"' => {
                    in_str = true;
                }
                b'{' | b'[' => {
                    depth += 1;
                }
                b'}' | b']' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some((i, j + 1));
                    }
                }
                _ => {}
            }
            j += 1;
        }
        None
    } else if first == b'"' {
        let mut j = i + 1;
        let mut escape = false;
        while j < bytes.len() {
            let c = bytes[j];
            if escape {
                escape = false;
            } else if c == b'\\' {
                escape = true;
            } else if c == b'"' {
                return Some((i, j + 1));
            }
            j += 1;
        }
        None
    } else {
        let mut j = i + 1;
        while j < bytes.len() {
            let c = bytes[j];
            if c == b',' || c == b')' || c == b';' || c.is_ascii_whitespace() {
                break;
            }
            j += 1;
        }
        Some((i, j))
    }
}

fn pkg_parse_prelude_tail(prelude: &str) -> Result<(Value, String, Value)> {
    let marker1 = "},\n{";
    let marker2 = "},\r\n{";
    let start = prelude
        .rfind(marker1)
        .map(|p| p + marker1.len() - 1)
        .or_else(|| prelude.rfind(marker2).map(|p| p + marker2.len() - 1))
        .context("pkg prelude: tail marker not found")?;

    let (vfs_s, vfs_e) = json_value_bounds(prelude, start).context("pkg prelude: vfs json")?;
    let vfs: Value =
        serde_json::from_str(&prelude[vfs_s..vfs_e]).context("pkg prelude: parse vfs")?;

    let mut i = vfs_e;
    while i < prelude.len()
        && (prelude.as_bytes()[i].is_ascii_whitespace() || prelude.as_bytes()[i] == b',')
    {
        i += 1;
    }
    let (ep_s, ep_e) = json_value_bounds(prelude, i).context("pkg prelude: entrypoint json")?;
    let ep_v: Value =
        serde_json::from_str(&prelude[ep_s..ep_e]).context("pkg prelude: parse entrypoint")?;
    let default_entrypoint = ep_v.as_str().unwrap_or("").to_string();

    i = ep_e;
    while i < prelude.len()
        && (prelude.as_bytes()[i].is_ascii_whitespace() || prelude.as_bytes()[i] == b',')
    {
        i += 1;
    }
    let (_sy_s, sy_e) = json_value_bounds(prelude, i).context("pkg prelude: symlinks json")?;
    i = sy_e;
    while i < prelude.len()
        && (prelude.as_bytes()[i].is_ascii_whitespace() || prelude.as_bytes()[i] == b',')
    {
        i += 1;
    }
    let (dict_s, dict_e) = json_value_bounds(prelude, i).context("pkg prelude: dict json")?;
    let dict: Value =
        serde_json::from_str(&prelude[dict_s..dict_e]).context("pkg prelude: parse dict")?;

    Ok((vfs, default_entrypoint, dict))
}

fn pkg_extract_text_js_from_payload(
    payload: &[u8],
    vfs: &Value,
    dict: &Value,
) -> Vec<(String, String)> {
    let mut inv: HashMap<String, String> = HashMap::new();
    if let Some(obj) = dict.as_object() {
        for (k, v) in obj {
            if let Some(id) = v.as_str() {
                inv.insert(id.to_string(), k.to_string());
            } else if let Some(n) = v.as_i64() {
                inv.insert(n.to_string(), k.to_string());
            }
        }
    }

    let mut out = Vec::new();
    let Some(vfs_obj) = vfs.as_object() else {
        return out;
    };

    for (path_ids, stores) in vfs_obj {
        let Some(stores_obj) = stores.as_object() else {
            continue;
        };

        let mut parts = Vec::new();
        let mut ok = true;
        for id in path_ids.split('/') {
            if let Some(name) = inv.get(id) {
                parts.push(name.clone());
            } else {
                ok = false;
                break;
            }
        }
        if !ok || parts.is_empty() {
            continue;
        }

        let filename = parts.last().cloned().unwrap_or_default();
        let is_js =
            filename.ends_with(".js") || filename.ends_with(".mjs") || filename.ends_with(".cjs");
        if !is_js {
            continue;
        }

        let display_path = normalize_pkg_snapshot_path(if cfg!(windows) {
            parts.join("\\")
        } else {
            parts.join("/")
        });

        let mut best: Option<&[u8]> = None;
        for (_store_key, range_val) in stores_obj {
            let Some(arr) = range_val.as_array() else {
                continue;
            };
            if arr.len() != 2 {
                continue;
            }
            let Some(off) = arr[0].as_u64() else { continue };
            let Some(len) = arr[1].as_u64() else { continue };
            let off = off as usize;
            let len = len as usize;
            if off.saturating_add(len) > payload.len() {
                continue;
            }
            let data = &payload[off..off + len];
            if !looks_like_utf8_text(data) {
                continue;
            }
            match best {
                None => best = Some(data),
                Some(prev) => {
                    if data.len() > prev.len() {
                        best = Some(data);
                    }
                }
            }
        }

        if let Some(data) = best {
            out.push((display_path, String::from_utf8_lossy(data).into_owned()));
        }
    }

    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn pkg_list_js_paths(vfs: &Value, dict: &Value) -> Vec<String> {
    let mut inv: HashMap<String, String> = HashMap::new();
    if let Some(obj) = dict.as_object() {
        for (k, v) in obj {
            if let Some(id) = v.as_str() {
                inv.insert(id.to_string(), k.to_string());
            } else if let Some(n) = v.as_i64() {
                inv.insert(n.to_string(), k.to_string());
            }
        }
    }

    let mut out = Vec::new();
    let Some(vfs_obj) = vfs.as_object() else {
        return out;
    };

    for (path_ids, _stores) in vfs_obj {
        let mut parts = Vec::new();
        let mut ok = true;
        for id in path_ids.split('/') {
            if let Some(name) = inv.get(id) {
                parts.push(name.clone());
            } else {
                ok = false;
                break;
            }
        }
        if !ok || parts.is_empty() {
            continue;
        }

        let filename = parts.last().cloned().unwrap_or_default();
        let is_js =
            filename.ends_with(".js") || filename.ends_with(".mjs") || filename.ends_with(".cjs");
        if !is_js {
            continue;
        }

        let display_path = normalize_pkg_snapshot_path(if cfg!(windows) {
            parts.join("\\")
        } else {
            parts.join("/")
        });
        out.push(display_path);
    }

    out.sort();
    out.dedup();
    out
}

pub trait Analyzer: Send + Sync {
    fn name(&self) -> &'static str;
    fn can_handle(&self, path: &Path, bytes: &[u8]) -> bool;
    fn analyze(&self, path: &Path, bytes: &[u8]) -> Result<AnalysisResult>;
    fn analyze_with_progress(
        &self,
        path: &Path,
        bytes: &[u8],
        _progress: &mut dyn FnMut(AnalysisProgress),
    ) -> Result<AnalysisResult> {
        self.analyze(path, bytes)
    }
}

fn decompress_gzip(data: &[u8]) -> std::io::Result<Vec<u8>> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut decoder = GzDecoder::new(data);
    let mut s = Vec::new();
    decoder.read_to_end(&mut s)?;
    Ok(s)
}

fn decompress_zlib(data: &[u8]) -> std::io::Result<Vec<u8>> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;
    let mut decoder = ZlibDecoder::new(data);
    let mut s = Vec::new();
    decoder.read_to_end(&mut s)?;
    Ok(s)
}

#[derive(Debug, Clone)]
pub struct AnalysisProgress {
    pub step: String,
    pub fraction: f32,
}

pub struct AnalysisEngine {
    analyzers: Vec<Box<dyn Analyzer>>,
    signature_engine: Option<SignatureEngine>,
}

impl Default for AnalysisEngine {
    fn default() -> Self {
        let mut engine = Self::new();
        engine.register(PyArmorAnalyzer);
        engine.register(PyInstallerExeAnalyzer);
        engine.register(PycAnalyzer);
        engine.register(BinaryAnalyzer);
        engine.register(SourceTextAnalyzer);
        engine.register(LuaAnalyzer);
        engine.register(UnknownAnalyzer);
        engine
    }
}

impl AnalysisEngine {
    pub fn new() -> Self {
        Self {
            analyzers: vec![],
            signature_engine: None,
        }
    }

    pub fn with_signature_engine(mut self, engine: SignatureEngine) -> Self {
        self.signature_engine = Some(engine);
        self
    }

    pub fn register<A: Analyzer + 'static>(&mut self, analyzer: A) {
        self.analyzers.push(Box::new(analyzer));
    }

    pub fn with_default_analyzers() -> Self {
        Self::default()
    }

    pub fn analyze_file_with_progress(
        &self,
        path: &Path,
        progress: &mut dyn FnMut(AnalysisProgress),
    ) -> Result<AnalysisResult> {
        let bytes = std::fs::read(path).with_context(|| format!("read file: {path:?}"))?;
        self.analyze_bytes_with_progress(path, &bytes, progress)
    }

    pub fn analyze_bytes_with_progress(
        &self,
        path: &Path,
        bytes: &[u8],
        progress: &mut dyn FnMut(AnalysisProgress),
    ) -> Result<AnalysisResult> {
        for analyzer in &self.analyzers {
            if analyzer.can_handle(path, bytes) {
                let mut res = analyzer
                    .analyze_with_progress(path, bytes, progress)
                    .with_context(|| analyzer.name())?;

                if let Some(sig_engine) = &self.signature_engine {
                    let matches = sig_engine.scan_bytes(bytes);
                    if !matches.is_empty() {
                        res.yara_matches.extend(matches);
                        res.yara_matches.sort();
                        res.yara_matches.dedup();
                    }
                }
                return Ok(res);
            }
        }
        anyhow::bail!("no analyzer available")
    }
}

pub fn extract_ascii_strings(bytes: &[u8], min_len: usize, max_strings: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = None::<usize>;
    for (i, &b) in bytes.iter().enumerate() {
        let is_printable = (0x20..=0x7e).contains(&b);
        if is_printable {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            let len = i - s;
            if len >= min_len
                && let Ok(text) = std::str::from_utf8(&bytes[s..i])
            {
                out.push(text.to_string());
                if out.len() >= max_strings {
                    break;
                }
            }
        }
    }
    if out.len() < max_strings
        && let Some(s) = start
    {
        let len = bytes.len().saturating_sub(s);
        if len >= min_len
            && let Ok(text) = std::str::from_utf8(&bytes[s..])
        {
            out.push(text.to_string());
        }
    }
    out
}

fn extract_urls_from_text(text: &str, out: &mut BTreeSet<String>) {
    let b = text.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        let rest = &b[i..];
        let scheme_len = if rest.starts_with(b"http://") {
            7
        } else if rest.starts_with(b"https://") {
            8
        } else {
            0
        };

        if scheme_len == 0 {
            i = i.saturating_add(1);
            continue;
        }

        let mut j = i.saturating_add(scheme_len);
        while j < b.len() {
            let c = b[j];
            let stop = c <= 0x20
                || matches!(
                    c,
                    b'"' | b'\'' | b'<' | b'>' | b'(' | b')' | b'[' | b']' | b'{' | b'}' | b'`'
                );
            if stop {
                break;
            }
            j = j.saturating_add(1);
        }

        if j > i + scheme_len {
            let mut url = String::from_utf8_lossy(&b[i..j]).to_string();
            while url.ends_with(['.', ',', ';', ':', '!', '?', ')', ']', '}', '"', '\'']) {
                url.pop();
            }
            if url.len() >= scheme_len + 3 && url.len() <= 2048 && url.contains('.') {
                out.insert(url);
            }
        }

        i = j.saturating_add(1);
    }
}

pub fn extract_urls(result: &AnalysisResult) -> Vec<String> {
    let mut set = BTreeSet::new();

    for ins in &result.disassembly {
        extract_urls_from_text(&ins.mnemonic, &mut set);
        extract_urls_from_text(&ins.op_str, &mut set);
    }

    for out in &result.external {
        extract_urls_from_text(&out.stdout, &mut set);
        extract_urls_from_text(&out.stderr, &mut set);
    }

    for s in &result.strings {
        extract_urls_from_text(s, &mut set);
    }

    for (_, code) in &result.deobfuscated_files {
        if code.len() <= 2 * 1024 * 1024 {
            extract_urls_from_text(code, &mut set);
        }
    }

    set.into_iter().collect()
}

fn truncate_text(mut s: String, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s;
    }
    s.truncate(max_chars.min(s.len()));
    s.push_str("\n…(truncation)\n");
    s
}

fn try_run_external_tool(
    tool: &str,
    args: Vec<OsString>,
    timeout: Duration,
) -> Result<ExternalToolOutput> {
    let mut cmd = Command::new(tool);
    #[cfg(windows)]
    cmd.creation_flags(0x08000000);
    cmd.args(args);

    let child = cmd.spawn().with_context(|| format!("spawn: {tool}"))?;
    let output = wait_with_timeout(child, timeout).with_context(|| format!("exec: {tool}"))?;

    Ok(ExternalToolOutput {
        tool: tool.to_string(),
        exit_code: output.status.code(),
        stdout: truncate_text(
            String::from_utf8_lossy(&output.stdout).into_owned(),
            200_000,
        ),
        stderr: truncate_text(
            String::from_utf8_lossy(&output.stderr).into_owned(),
            200_000,
        ),
    })
}

fn wait_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> std::io::Result<std::process::Output> {
    let start = std::time::Instant::now();
    loop {
        match child.try_wait()? {
            Some(_status) => return child.wait_with_output(),
            None => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

fn run_first_available_tool(
    candidates: &[(&str, Vec<OsString>)],
    timeout: Duration,
) -> (Vec<ExternalToolOutput>, Vec<String>) {
    let mut warnings = Vec::new();
    for (tool, args) in candidates {
        match try_run_external_tool(tool, args.clone(), timeout) {
            Ok(out) => return (vec![out], warnings),
            Err(e) => {
                if let Some(ioe) = e.downcast_ref::<std::io::Error>()
                    && ioe.kind() == std::io::ErrorKind::NotFound
                {
                    continue;
                }
                warnings.push(format!("{tool}: {e:#}"));
            }
        }
    }
    // warnings.push("no external tool found on PATH".to_string());
    (Vec::new(), warnings)
}

fn disassemble(
    cs: &Capstone,
    code: &[u8],
    start_address: u64,
    max_instructions: usize,
) -> Result<Vec<InstructionLine>> {
    let insns = cs
        .disasm_all(code, start_address)
        .context("capstone disasm_all")?;

    let mut out = Vec::new();
    for i in insns.iter().take(max_instructions) {
        let bytes_hex = i
            .bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");

        out.push(InstructionLine {
            address: i.address(),
            bytes_hex,
            mnemonic: i.mnemonic().unwrap_or("").to_string(),
            op_str: i.op_str().unwrap_or("").to_string(),
        });
    }
    Ok(out)
}

fn capstone_for_pe_machine(machine: u16) -> Option<Capstone> {
    match machine {
        0x014c => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .syntax(arch::x86::ArchSyntax::Intel)
            .build()
            .ok(),
        0x8664 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .build()
            .ok(),
        0x01c0 => Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Arm)
            .build()
            .ok(),
        0xaa64 => Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .build()
            .ok(),
        _ => None,
    }
}

fn capstone_for_elf(elf: &goblin::elf::Elf) -> Option<Capstone> {
    match elf.header.e_machine {
        goblin::elf::header::EM_386 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .syntax(arch::x86::ArchSyntax::Intel)
            .build()
            .ok(),
        goblin::elf::header::EM_X86_64 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .build()
            .ok(),
        goblin::elf::header::EM_ARM => Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Arm)
            .build()
            .ok(),
        goblin::elf::header::EM_AARCH64 => Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .build()
            .ok(),
        _ => None,
    }
}

pub struct BinaryAnalyzer;

fn pe_imports(pe: &goblin::pe::PE) -> Vec<String> {
    let mut out = BTreeSet::new();
    for imp in &pe.imports {
        let dll = imp.dll.to_string();
        let name = imp.name.to_string();
        if !name.is_empty() {
            out.insert(format!("{dll}!{name}"));
        } else {
            out.insert(format!("{dll}!#{}", imp.ordinal));
        }
    }
    out.into_iter().collect()
}

fn fast_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }

    let first = needle[0];
    let mut i = 0;
    let max = haystack.len() - needle.len();

    while i <= max {
        if haystack[i] == first && &haystack[i..i + needle.len()] == needle {
            return true;
        }
        i += 1;
    }
    false
}

fn detect_js_container(bytes: &[u8]) -> Option<String> {
    let is_pkg = fast_contains(bytes, b"PAYLOAD_POSITION");
    if is_pkg {
        return Some("pkg".to_string());
    }

    let is_electron = fast_contains(bytes, b"resources\\app.asar")
        || fast_contains(bytes, b"resources/app.asar")
        || fast_contains(bytes, b"app.asar")
        || fast_contains(bytes, b"electron.asar")
        || fast_contains(bytes, b"chrome_100_percent.pak")
        || fast_contains(bytes, b"icudtl.dat")
        || fast_contains(bytes, b"v8_context_snapshot.bin");
    if is_electron {
        return Some("electron".to_string());
    }

    let is_nwjs = fast_contains(bytes, b"nwjs")
        || fast_contains(bytes, b"node-webkit")
        || fast_contains(bytes, b"nw.pak");
    if is_nwjs {
        return Some("nwjs".to_string());
    }

    let is_node = fast_contains(bytes, b"node_modules")
        || fast_contains(bytes, b"require(")
        || fast_contains(bytes, b"module.exports")
        || fast_contains(bytes, b"process.env");
    if is_node {
        return Some("nodejs".to_string());
    }

    None
}

fn detect_js_obfuscation(text: &str) -> bool {
    let t = text.as_bytes();
    if t.len() < 100 {
        return false;
    }

    let mut score = 0u8;
    let lc = text.to_ascii_lowercase();

    if lc.contains("eval(") {
        score = score.saturating_add(2);
    }
    if lc.contains("function(") && lc.contains("return ") && lc.contains("})(") {
        score = score.saturating_add(1);
    }
    if lc.contains("atob(") || lc.contains("btoa(") {
        score = score.saturating_add(1);
    }
    if lc.contains("string.fromcharcode") {
        score = score.saturating_add(1);
    }
    if lc.contains("unescape(") {
        score = score.saturating_add(1);
    }
    if lc.contains("\\x") || lc.contains("\\u") {
        score = score.saturating_add(1);
    }
    if lc.contains("_0x") {
        score = score.saturating_add(2);
    }
    if lc.contains("[0x") {
        score = score.saturating_add(2);
    }
    if lc.contains("__p_") {
        score = score.saturating_add(2);
    }

    let hex_count = lc.matches("0x").count();
    if hex_count >= 10 {
        score = score.saturating_add(1);
    }
    if hex_count >= 25 {
        score = score.saturating_add(1);
    }

    if lc.contains("<<") || lc.contains(">>") || lc.contains("^") {
        score = score.saturating_add(1);
    }

    // Check for comma-heavy variable declarations often used in obfuscation
    if (lc.contains("var ") || lc.contains("const ") || lc.contains("let "))
        && lc.matches(',').count() >= 15
    {
        score = score.saturating_add(1);
    }

    let mut printable = 0usize;
    let mut non_printable = 0usize;
    for &b in t {
        if b == b'\n' || b == b'\r' || b == b'\t' || (0x20..=0x7e).contains(&b) {
            printable += 1;
        } else {
            non_printable += 1;
        }
    }
    if non_printable > 0 && printable > 0 {
        let ratio = (non_printable as f32) / ((printable + non_printable) as f32);
        if ratio > 0.10 {
            score = score.saturating_add(2);
        }
    }

    let mut ident_runs = 0usize;
    let mut current = 0usize;
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '$' {
            current += 1;
        } else {
            if current >= 15 {
                ident_runs += 1;
            }
            current = 0;
        }
    }
    if current >= 15 {
        ident_runs += 1;
    }
    if ident_runs >= 3 {
        score = score.saturating_add(2);
    }

    if score >= 4 {
        return true;
    }

    let mut max_line_len = 0usize;
    let mut whitespace = 0usize;
    for line in text.lines() {
        max_line_len = max_line_len.max(line.len());
    }
    for ch in text.chars() {
        if ch.is_ascii_whitespace() {
            whitespace += 1;
        }
    }
    let whitespace_ratio = (whitespace as f32) / (text.len().max(1) as f32);
    max_line_len >= 800 && whitespace_ratio <= 0.05
}

fn work_dir_in_appdata(prefix: &str) -> PathBuf {
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    base.join("Singularity")
        .join("work")
        .join(format!("{prefix}_{id}"))
}

fn ensure_pyinstxtractor_ng(progress: &mut dyn FnMut(AnalysisProgress)) -> Result<PathBuf> {
    if !cfg!(windows) {
        anyhow::bail!("pyinstxtractor-ng.exe is only supported on Windows in Singularity");
    }

    let url = "https://github.com/pyinstxtractor/pyinstxtractor-ng/releases/download/2025.01.05/pyinstxtractor-ng.exe";
    let tm = ToolManager::global();
    let tools_dir = tm.get_tools_dir();
    let dst = tools_dir.join("pyinstxtractor-ng.exe");

    if !dst.exists() {
        progress(AnalysisProgress {
            step: "Downloading pyinstxtractor-ng...".to_string(),
            fraction: 0.20,
        });
    }

    tm.get_or_download_tool("pyinstxtractor-ng", url, "pyinstxtractor-ng.exe")
}

fn run_pyinstxtractor_ng(
    tool_path: &Path,
    target: &Path,
    cwd: &Path,
) -> Result<ExternalToolOutput> {
    let mut cmd = Command::new(tool_path);
    #[cfg(windows)]
    cmd.creation_flags(0x08000000);
    cmd.arg(target)
        .current_dir(cwd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let out = cmd.output().context("pyinstxtractor-ng run")?;
    Ok(ExternalToolOutput {
        tool: "pyinstxtractor-ng".to_string(),
        exit_code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else if ty.is_file() {
            let _ = std::fs::create_dir_all(dst);
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

fn collect_files_recursive(root: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let p = entry.path();
        if ty.is_dir() {
            collect_files_recursive(&p, out)?;
        } else if ty.is_file() {
            out.push(p);
        }
    }
    Ok(())
}

fn try_relativize(root: &Path, path: &Path) -> String {
    match path.strip_prefix(root) {
        Ok(r) => r.to_string_lossy().to_string(),
        Err(_) => path.to_string_lossy().to_string(),
    }
}

fn attempt_7zip_fallback(
    target_exe: &Path,
    work_dir: &Path,
    warnings: &mut Vec<String>,
) -> Result<Option<PathBuf>> {
    let tm = ToolManager::global();
    let seven_z = match tm.setup_7zip() {
        Ok(p) => p,
        Err(e) => {
            warnings.push(format!("electron: 7-zip setup failed: {e:#}"));
            return Ok(None);
        }
    };

    let extract_dir = work_dir.join("7z_extracted");
    let _ = std::fs::remove_dir_all(&extract_dir);
    std::fs::create_dir_all(&extract_dir)?;

    // 1. Extract EXE
    run_7zip(&seven_z, target_exe, &extract_dir)?;

    // 2. Recursive Search
    recursive_7zip_search(&extract_dir, &seven_z, 0)
}

fn run_7zip(seven_z: &Path, target: &Path, out_dir: &Path) -> Result<()> {
    let mut cmd = Command::new(seven_z);
    #[cfg(windows)]
    cmd.creation_flags(0x08000000);

    cmd.arg("x")
        .arg("-y")
        .arg(format!("-o{}", out_dir.display()))
        .arg(target);

    let _ = cmd.output();
    Ok(())
}

fn recursive_7zip_search(dir: &Path, seven_z: &Path, depth: usize) -> Result<Option<PathBuf>> {
    if depth > 3 {
        return Ok(None);
    }

    let mut all_files = Vec::new();
    if collect_files_recursive(dir, &mut all_files).is_err() {
        return Ok(None);
    }

    // 1. Search for ASAR
    for p in &all_files {
        let name = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();
        if name == "app.asar" || name == "electron.asar" || name.ends_with(".asar") {
            return Ok(Some(p.clone()));
        }
    }

    // 2. Search for Archives
    for p in &all_files {
        let name = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();
        if name.ends_with(".zip") || name.ends_with(".7z") || name.ends_with(".rar") {
            let sub_out = p.with_extension("extracted_subdir");
            if !sub_out.exists() {
                run_7zip(seven_z, p, &sub_out)?;
                if let Some(res) = recursive_7zip_search(&sub_out, seven_z, depth + 1)? {
                    return Ok(Some(res));
                }
            }
        }
    }

    Ok(None)
}

fn run_npx_asar_extract(asar_path: &Path, out_dir: &Path) -> Result<ExternalToolOutput> {
    let npx = if cfg!(windows) { "npx.cmd" } else { "npx" };
    let mut cmd = Command::new(npx);
    #[cfg(windows)]
    cmd.creation_flags(0x08000000);
    cmd.arg("--yes")
        .arg("asar")
        .arg("extract")
        .arg(asar_path)
        .arg(out_dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let output = cmd.output().context("npx asar extract")?;
    Ok(ExternalToolOutput {
        tool: "npx asar extract".to_string(),
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

fn cleaned_js_path(original: &Path) -> PathBuf {
    let parent = original.parent().unwrap_or_else(|| Path::new(""));
    let stem = original.file_stem().unwrap_or_default().to_string_lossy();
    let cleaned_stem = format!("{stem}_cleaned");
    if let Some(ext) = original.extension().and_then(|e| e.to_str()) {
        parent.join(format!("{cleaned_stem}.{ext}"))
    } else {
        parent.join(cleaned_stem)
    }
}

#[allow(clippy::too_many_arguments)]
fn electron_extract_asar_and_sources(
    target_exe: &Path,
    work_dir: &Path,
    deobfuscated_files: &mut Vec<(String, String)>,
    deobfuscated_file_locations: &mut Vec<(String, String)>,
    strings: &mut Vec<String>,
    js_obfuscated: &mut bool,
    external: &mut Vec<ExternalToolOutput>,
    warnings: &mut Vec<String>,
    progress: &mut dyn FnMut(AnalysisProgress),
    js_files_out: &mut Vec<JsFileInfo>,
) -> Result<()> {
    progress(AnalysisProgress {
        step: "Preparing Electron analysis...".to_string(),
        fraction: 0.10,
    });

    std::fs::create_dir_all(&work_dir)?;

    let npx_ok = is_command_available("npx")
        || (cfg!(windows) && is_command_available("npx.cmd"))
        || (cfg!(windows) && is_command_available("node") && is_command_available("npm.cmd"));
    if !npx_ok {
        let tm = ToolManager::global();
        tm.ensure_tools_available();
        warnings.push(
            "electron: Node.js/npx not available. Installing tools in background; Re-analyze once installation is finished."
                .to_string(),
        );
        progress(AnalysisProgress {
            step: "Installing missing dependencies...".to_string(),
            fraction: 1.0,
        });
        let _ = std::fs::remove_dir_all(&work_dir);
        return Ok(());
    }

    progress(AnalysisProgress {
        step: "Searching for embedded resources...".to_string(),
        fraction: 0.20,
    });

    let mut asar_path: Option<PathBuf> = None;
    let mut extraction_note: Option<String> = None;

    if let Some(parent) = target_exe.parent() {
        let external_candidates = [
            parent.join("resources").join("app.asar"),
            parent.join("resources").join("default_app.asar"),
            parent.join("app.asar"),
        ];
        for c in external_candidates {
            if c.exists() {
                let copied = work_dir.join(
                    c.file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string(),
                );
                if std::fs::copy(&c, &copied).is_ok() {
                    asar_path = Some(copied);
                    extraction_note =
                        Some(format!("electron: found external asar at {}", c.display()));
                    break;
                }
            }
        }
    }

    if asar_path.is_none() {
        progress(AnalysisProgress {
            step: "Extracting embedded ASAR archive...".to_string(),
            fraction: 0.35,
        });
        match asar_ripper::extract_first_appended_asar(target_exe, &work_dir) {
            Ok(Some(ex)) => {
                extraction_note = Some(format!(
                    "electron: extracted appended asar at offset 0x{:x}",
                    ex.header_offset
                ));
                asar_path = Some(ex.asar_path);
            }
            Ok(None) => {}
            Err(e) => {
                warnings.push(format!("electron: asar ripper error: {e:#}"));
            }
        }

        if asar_path.is_none() {
            progress(AnalysisProgress {
                step: "Attempting 7-Zip fallback...".to_string(),
                fraction: 0.45,
            });
            match attempt_7zip_fallback(target_exe, &work_dir, warnings) {
                Ok(Some(p)) => {
                    asar_path = Some(p);
                    // extraction_note = Some("electron: found asar via 7-zip fallback".to_string());
                }
                Ok(None) => {}
                Err(e) => {
                    warnings.push(format!("electron: 7-zip fallback error: {e:#}"));
                }
            }
        }
    }

    if let Some(note) = extraction_note {
        warnings.push(note);
    }

    let unpack_dir = work_dir.join("asar_unpacked");
    let fallback_dir = work_dir.join("7z_extracted");

    let mut scan_roots = Vec::new();

    if let Some(asar_path) = asar_path {
        progress(AnalysisProgress {
            step: "Running npx asar extract...".to_string(),
            fraction: 0.55,
        });

        let _ = std::fs::remove_dir_all(&unpack_dir);
        std::fs::create_dir_all(&unpack_dir)?;

        match run_npx_asar_extract(&asar_path, &unpack_dir) {
            Ok(out) => {
                let ok = out.exit_code.unwrap_or(1) == 0;
                external.push(out);
                if ok {
                    scan_roots.push(unpack_dir.clone());
                } else {
                    warnings.push("electron: npx asar extract failed".to_string());
                }
            }
            Err(e) => {
                warnings.push(format!("electron: npx asar extract error: {e:#}"));
            }
        }
    }

    if fallback_dir.exists()
        && std::fs::read_dir(&fallback_dir)
            .map(|mut i| i.next().is_some())
            .unwrap_or(false)
    {
        if scan_roots.is_empty() {
            warnings.push(
                "electron: no app.asar found, scanning 7-Zip extracted files directly".to_string(),
            );
        } else {
            // warnings.push("electron: scanning both asar content and 7-Zip extracted files".to_string());
        }
        scan_roots.push(fallback_dir.clone());
    }

    if scan_roots.is_empty() {
        warnings.push(
            "electron: no content found to analyze (no asar extracted and no fallback files)"
                .to_string(),
        );
        return Ok(());
    }

    progress(AnalysisProgress {
        step: "Scanning extracted files...".to_string(),
        fraction: 0.75,
    });

    let mut all_files = Vec::new();
    for root in &scan_roots {
        // warnings.push(format!("electron: scanning root: {}", root.display()));
        if let Err(e) = collect_files_recursive(root, &mut all_files) {
            warnings.push(format!(
                "electron: file walk error in {}: {e:#}",
                root.display()
            ));
        }
    }
    all_files.sort();

    // warnings.push(format!("electron: found {} total files in scan roots", all_files.len()));

    let mut js_files = all_files
        .into_iter()
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .map(|e| matches!(e.to_ascii_lowercase().as_str(), "js" | "mjs" | "cjs"))
                .unwrap_or(false)
        })
        .filter(|p| {
            !p.components()
                .any(|c| c.as_os_str().eq_ignore_ascii_case("node_modules"))
        })
        .collect::<Vec<_>>();

    js_files.sort_by_key(|p| (p.components().count(), p.to_string_lossy().len()));

    // warnings.push(format!("electron: found {} interesting JS files (excluding node_modules)", js_files.len()));
    if js_files.is_empty() {
        warnings.push("electron: warning: no JS files found after filtering!".to_string());
    } else {
        // Log first 5 files for debugging
        // for p in js_files.iter().take(5) {
        //     warnings.push(format!("electron: will analyze: {}", p.display()));
        // }
    }

    let mut sync_avail = synchrony_available();
    let mut requested_sync_install = false;
    let mut extracted_rel_locations: Vec<(String, PathBuf)> = Vec::new();
    let total_js_files = js_files.len();

    for (idx, p) in js_files.into_iter().enumerate() {
        let display_name = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        progress(AnalysisProgress {
            step: format!(
                "Analyzing {} ({}/{})",
                display_name,
                idx + 1,
                total_js_files
            ),
            fraction: 0.75 + 0.15 * ((idx + 1) as f32 / total_js_files.max(1) as f32),
        });

        if idx >= 200 {
            warnings.push("electron: too many js files, truncated extraction".to_string());
            break;
        }

        // Removed 2MB limit as requested by user to support large bundled JS files
        // let meta = std::fs::metadata(&p).ok();
        // if meta
        //     .as_ref()
        //     .map(|m| m.len() > 2 * 1024 * 1024)
        //     .unwrap_or(false)
        // {
        //     continue;
        // }

        let data = match std::fs::read(&p) {
            Ok(d) => d,
            Err(_) => continue,
        };

        let text = match String::from_utf8(data.clone()) {
            Ok(s) => s,
            Err(_) => {
                // Not utf8, skip
                continue;
            }
        };

        let is_obf = detect_js_obfuscation(&text);
        if is_obf {
            // warnings.push(format!("electron: detected obfuscation in {}", p.file_name().unwrap_or_default().to_string_lossy()));
        }
        *js_obfuscated |= is_obf;

        let mut file_info = JsFileInfo {
            name: String::new(), // Will be set later
            original: Some(text.clone()),
            synchrony: None,
            path: p.to_string_lossy().to_string(),
            size: data.len() as u64,
        };

        if is_obf && !sync_avail {
            sync_avail = synchrony_available();
        }

        if is_obf && !sync_avail && !requested_sync_install {
            let tm = ToolManager::global();
            tm.ensure_tools_available();
            requested_sync_install = true;
            warnings.push("JS obfuscation detected; installing synchrony (deobfuscator). Re-analyze once installation is finished.".to_string());
        }

        let cleaned_rel = try_relativize(&work_dir, &p);
        file_info.name = cleaned_rel.clone();

        extracted_rel_locations.push((cleaned_rel.clone(), PathBuf::from(cleaned_rel.clone())));
        deobfuscated_files.push((cleaned_rel.clone(), text.clone()));

        if is_obf && sync_avail {
            progress(AnalysisProgress {
                step: format!("Deobfuscating {} with Synchrony...", display_name),
                fraction: 0.75 + 0.15 * ((idx + 1) as f32 / total_js_files.max(1) as f32),
            });
            match run_synchrony_capture(&p) {
                Ok((code, cleaned_path_opt)) => {
                    file_info.synchrony = Some(code.clone());

                    let cleaned_path = cleaned_path_opt
                        .clone()
                        .unwrap_or_else(|| cleaned_js_path(&p));
                    if !cleaned_path.exists() {
                        let _ = std::fs::write(&cleaned_path, code.as_bytes());
                    }

                    let cleaned_rel_path = try_relativize(&work_dir, &cleaned_path);

                    // Replace the original content with deobfuscated one in the list

                    merge_strings(
                        strings,
                        extract_ascii_strings(code.as_bytes(), 6, 200),
                        3000,
                    );

                    extracted_rel_locations.pop();
                    deobfuscated_files.pop();

                    extracted_rel_locations.push((
                        cleaned_rel_path.clone(),
                        PathBuf::from(cleaned_rel_path.clone()),
                    ));
                    deobfuscated_files.push((cleaned_rel_path.clone(), code.clone()));

                    file_info.name = cleaned_rel_path;
                }
                Err(_) => {
                    merge_strings(
                        strings,
                        extract_ascii_strings(text.as_bytes(), 6, 200),
                        3000,
                    );
                }
            }
        } else {
            merge_strings(
                strings,
                extract_ascii_strings(text.as_bytes(), 6, 200),
                3000,
            );
        }

        js_files_out.push(file_info);
    }

    progress(AnalysisProgress {
        step: "Copying extracted files".to_string(),
        fraction: 0.90,
    });

    let appdata = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let singularity_root = appdata.join("Singularity");
    let _ = std::fs::create_dir_all(&singularity_root);

    let mut output_dir: Option<PathBuf> = None;

    {
        let base = target_exe
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let dst = singularity_root.join(format!("singularity_extracted_{base}_{id}"));

        let mut copy_ok = true;
        for root in &scan_roots {
            let dirname = root.file_name().unwrap_or_default();
            let target_subdir = dst.join(dirname);
            if let Err(e) = copy_dir_recursive(root, &target_subdir) {
                warnings.push(format!(
                    "electron: failed to copy extracted files from {}: {e:#}",
                    root.display()
                ));
                copy_ok = false;
            }
        }

        if copy_ok {
            output_dir = Some(dst.clone());
        }
    }

    let location_base = output_dir.unwrap_or(work_dir.to_path_buf());
    for (display, rel_path) in extracted_rel_locations {
        let abs = location_base.join(rel_path);
        deobfuscated_file_locations.push((display, abs.to_string_lossy().to_string()));
    }

    progress(AnalysisProgress {
        step: "Finalizing analysis results...".to_string(),
        fraction: 1.0,
    });

    Ok(())
}

fn merge_strings(into: &mut Vec<String>, extra: Vec<String>, max: usize) {
    if into.len() >= max {
        return;
    }
    let mut seen: HashMap<String, ()> = into.iter().cloned().map(|s| (s, ())).collect();
    for s in extra {
        if into.len() >= max {
            break;
        }
        if !seen.contains_key(&s) {
            seen.insert(s.clone(), ());
            into.push(s);
        }
    }
}

fn collect_secrets(
    strings: &[String],
    deobfuscated_files: &[(String, String)],
    js_files: &[JsFileInfo],
    disassembly: &[InstructionLine],
    external: &[ExternalToolOutput],
) -> Vec<SecretMatch> {
    let mut matches = Vec::new();

    for s in strings {
        matches.extend(secrets::scan_text(s));
    }

    for (_, content) in deobfuscated_files {
        // Limit content size to avoid hanging on huge files?
        // secrets::scan_text should handle it, but let's be safe.
        if content.len() < 5 * 1024 * 1024 {
            matches.extend(secrets::scan_text(content));
        }
    }

    for js in js_files {
        if let Some(code) = &js.original {
            if code.len() < 5 * 1024 * 1024 {
                matches.extend(secrets::scan_text(code));
            }
        }
        if let Some(code) = &js.synchrony {
            if code.len() < 5 * 1024 * 1024 {
                matches.extend(secrets::scan_text(code));
            }
        }
    }

    for line in disassembly {
        matches.extend(secrets::scan_text(&line.op_str));
    }

    for ext in external {
        matches.extend(secrets::scan_text(&ext.stdout));
    }

    matches.sort_by(|a, b| a.value.cmp(&b.value));
    matches.dedup_by(|a, b| a.value == b.value);

    matches
}

fn calculate_confidence_score(result: &AnalysisResult) -> u8 {
    if result.is_stealer {
        return 10;
    }

    let mut score: u8 = 1;

    if result.js_container.is_some() {
        score = score.saturating_add(2);
    }
    let has_text_js = result.deobfuscated_files.iter().any(|(n, c)| {
        (n.ends_with(".js") || n.ends_with(".mjs") || n.ends_with(".cjs"))
            && !c.contains("snapshot/bytecode")
    });
    if has_text_js {
        score = score.saturating_add(3);
    }
    if result
        .deobfuscated_files
        .iter()
        .any(|(n, _)| n.starts_with("carved_") || n.starts_with("carved_snapshot"))
    {
        score = score.saturating_add(2);
    }
    if result.js_obfuscated {
        score = score.saturating_add(2);
    }

    let urls = extract_urls(result);
    if !urls.is_empty() {
        score = score.saturating_add(1);
        if urls.len() >= 5 {
            score = score.saturating_add(1);
        }
    }

    score.min(10)
}

fn detect_embedded_lua(strings: &[String]) -> Option<String> {
    for s in strings {
        if s.contains("lua_State") || s.contains("luaL_newstate") || s.contains("lua_open") {
            return Some("Lua (Embedded API)".to_string());
        }
        if s.contains("Lua 5.0") {
            return Some("Lua 5.0".to_string());
        }
        if s.contains("Lua 5.1") {
            return Some("Lua 5.1".to_string());
        }
        if s.contains("Lua 5.2") {
            return Some("Lua 5.2".to_string());
        }
        if s.contains("Lua 5.3") {
            return Some("Lua 5.3".to_string());
        }
        if s.contains("Lua 5.4") {
            return Some("Lua 5.4".to_string());
        }
        if s.contains("LuaJIT") {
            return Some("LuaJIT".to_string());
        }
        if s.contains("PANIC: unprotected error in call to Lua API") {
            return Some("Lua (Panic String)".to_string());
        }
    }
    None
}

fn detect_numbered_electron_variant(path: &Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    // Check if we have files named "0", "1", "2"
    let has_0 = parent.join("0").exists();
    let has_1 = parent.join("1").exists();
    let has_2 = parent.join("2").exists();

    // Check if current file name is a number
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let is_number = name.chars().all(|c| c.is_ascii_digit());

    (has_0 && has_1 && has_2) || (is_number && (has_0 || has_1))
}

impl Analyzer for BinaryAnalyzer {
    fn name(&self) -> &'static str {
        "binary"
    }

    fn can_handle(&self, _path: &Path, bytes: &[u8]) -> bool {
        match Object::parse(bytes) {
            Ok(Object::PE(_))
            | Ok(Object::Elf(_))
            | Ok(Object::Mach(_))
            | Ok(Object::Archive(_)) => true,
            _ => false,
        }
    }

    fn analyze(&self, path: &Path, bytes: &[u8]) -> Result<AnalysisResult> {
        let mut noop = |_| {};
        self.analyze_with_progress(path, bytes, &mut noop)
    }

    fn analyze_with_progress(
        &self,
        path: &Path,
        bytes: &[u8],
        progress: &mut dyn FnMut(AnalysisProgress),
    ) -> Result<AnalysisResult> {
        progress(AnalysisProgress {
            step: "Analyzing binary structure...".to_string(),
            fraction: 0.05,
        });

        let mut warnings = Vec::new();
        let mut sections = Vec::new();
        let mut entry_point = None::<u64>;
        let mut disassembly = Vec::new();
        let mut external = Vec::new();
        let mut imports = Vec::new();
        let mut deobfuscated_files = Vec::new();
        let mut deobfuscated_file_locations = Vec::new();
        let mut js_files = Vec::new();
        let work_dir = work_dir_in_appdata("scan");

        let mut strings = extract_ascii_strings(bytes, 4, 3000);
        let mut js_container = detect_js_container(bytes);
        let mut js_obfuscated = false;
        let mut language = "Native".to_string();

        let mut kind = match Object::parse(bytes).context("goblin parse")? {
            Object::PE(pe) => {
                entry_point = Some(pe.image_base as u64 + pe.entry as u64);
                imports = pe_imports(&pe);

                for s in &pe.sections {
                    sections.push(SectionInfo {
                        name: s.name().unwrap_or("").to_string(),
                        virtual_address: Some(s.virtual_address as u64 + pe.image_base as u64),
                        virtual_size: Some(s.virtual_size as u64),
                        file_offset: Some(s.pointer_to_raw_data as u64),
                        file_size: Some(s.size_of_raw_data as u64),
                    });
                }

                if let Some(cs) = capstone_for_pe_machine(pe.header.coff_header.machine) {
                    if let Some(ep) = entry_point {
                        let rva = (ep - pe.image_base as u64) as u32;
                        if let Some((code, base_addr)) = pe_code_slice_for_rva(&pe, bytes, rva) {
                            disassembly =
                                disassemble(&cs, code, base_addr, 500).unwrap_or_else(|e| {
                                    warnings.push(format!("disassembly: {e:#}"));
                                    Vec::new()
                                });
                        } else {
                            warnings.push("entry: section not found for disassembly".to_string());
                        }
                    }
                } else {
                    warnings.push("unsupported PE architecture for disassembly".to_string());
                }

                let p = path.to_path_buf();
                let mut candidates: Vec<(&str, Vec<OsString>)> = Vec::new();

                if matches!(js_container.as_deref(), Some("pkg")) {
                    let payload_marker = b"PAYLOAD_POSITION";
                    let mut found_payload = false;
                    let mut current_pos = 0usize;

                    let parse_quoted_usize = |text: &str, name: &str| -> Option<usize> {
                        let idx = text.find(name)?;
                        let after = &text[idx..];
                        let eq_pos = after.find('=')?;
                        let after_eq = &after[eq_pos..];
                        let q1 = after_eq.find('\'')?;
                        let after_q1 = &after_eq[q1 + 1..];
                        let q2 = after_q1.find('\'')?;
                        after_q1[..q2].trim().parse::<usize>().ok()
                    };

                    while let Some(pos_idx) = bytes[current_pos..]
                        .windows(payload_marker.len())
                        .position(|w| w == payload_marker)
                    {
                        let absolute_pos = current_pos + pos_idx;
                        current_pos = absolute_pos + payload_marker.len();

                        let lookahead =
                            &bytes[absolute_pos..std::cmp::min(absolute_pos + 1200, bytes.len())];
                        let s = String::from_utf8_lossy(lookahead);

                        let Some(payload_pos) = parse_quoted_usize(&s, "PAYLOAD_POSITION") else {
                            continue;
                        };
                        let Some(payload_size) = parse_quoted_usize(&s, "PAYLOAD_SIZE") else {
                            continue;
                        };
                        let Some(prelude_pos) = parse_quoted_usize(&s, "PRELUDE_POSITION") else {
                            continue;
                        };
                        let Some(prelude_size) = parse_quoted_usize(&s, "PRELUDE_SIZE") else {
                            continue;
                        };

                        if payload_pos.saturating_add(payload_size) > bytes.len() {
                            continue;
                        }
                        if prelude_pos.saturating_add(prelude_size) > bytes.len() {
                            continue;
                        }

                        found_payload = true;
                        let payload_data = &bytes[payload_pos..payload_pos + payload_size];
                        let prelude_bytes = &bytes[prelude_pos..prelude_pos + prelude_size];
                        let prelude_text = String::from_utf8_lossy(prelude_bytes).into_owned();

                        match pkg_parse_prelude_tail(&prelude_text) {
                            Ok((vfs, default_entrypoint, dict)) => {
                                let _ = default_entrypoint;

                                let mut payload_decompressed = Vec::new();
                                let payload_for_vfs: &[u8] = if payload_data
                                    .starts_with(&[0x1f, 0x8b])
                                {
                                    let mut d = flate2::read::GzDecoder::new(payload_data);
                                    match d.read_to_end(&mut payload_decompressed) {
                                        Ok(_) => payload_decompressed.as_slice(),
                                        Err(e) => {
                                            warnings.push(format!(
                                                "pkg payload gzip decompression failed: {e}. Using raw payload."
                                            ));
                                            payload_data
                                        }
                                    }
                                } else {
                                    payload_data
                                };

                                let sync_avail = synchrony_available();
                                let mut need_sync_install = false;
                                let base = path
                                    .file_stem()
                                    .unwrap_or_default()
                                    .to_string_lossy()
                                    .to_string();
                                let id = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_millis())
                                    .unwrap_or(0);
                                let output_dir = std::env::current_exe()
                                    .ok()
                                    .and_then(|p| p.parent().map(|p| p.to_path_buf()))
                                    .map(|dir| {
                                        dir.join(format!("singularity_extracted_{base}_{id}"))
                                            .join("pkg")
                                    });
                                if let Some(dir) = &output_dir {
                                    let _ = std::fs::create_dir_all(dir);
                                    warnings.push(format!(
                                        "pkg: wrote extracted files to {}",
                                        dir.display()
                                    ));
                                }
                                let temp_dir = std::env::temp_dir().join("singularity_pkg_extract");
                                let _ = std::fs::create_dir_all(&temp_dir);
                                let out_dir = output_dir.unwrap_or(temp_dir);

                                let extracted =
                                    pkg_extract_text_js_from_payload(payload_for_vfs, &vfs, &dict);
                                let _js_paths = pkg_list_js_paths(&vfs, &dict);
                                if extracted.is_empty() {
                                    warnings.push(
                                         "pkg: no textual .js found in payload (bytecode/snapshot only)"
                                             .to_string(),
                                     );
                                    // Do not add placeholders to deobfuscated_files, so the button doesn't show up empty.

                                    let snippets = carve_probable_js_snippets(payload_for_vfs);
                                    let snippets = if snippets.is_empty() {
                                        carve_js_keyword_windows(payload_for_vfs)
                                    } else {
                                        snippets
                                    };
                                    if !snippets.is_empty() {
                                        warnings.push(format!(
                                            "pkg: found {} probable JS snippet(s) in snapshot",
                                            snippets.len()
                                        ));
                                        for (idx, snippet) in snippets.into_iter().enumerate() {
                                            progress(AnalysisProgress {
                                                step: format!(
                                                    "Analyzing carved snippet {}...",
                                                    idx + 1
                                                ),
                                                fraction: 0.85,
                                            });
                                            let name =
                                                format!("carved_snapshot_snippet_{idx:02}.js");
                                            let js_path = out_dir.join(format!("{idx:03}_{name}"));
                                            let is_obf = detect_js_obfuscation(&snippet);
                                            js_obfuscated |= is_obf;

                                            merge_strings(
                                                &mut strings,
                                                extract_ascii_strings(snippet.as_bytes(), 6, 200),
                                                3000,
                                            );

                                            if is_obf && !sync_avail {
                                                need_sync_install = true;
                                                if std::fs::write(&js_path, snippet.as_bytes())
                                                    .is_ok()
                                                {
                                                    deobfuscated_file_locations.push((
                                                        name.clone(),
                                                        js_path.to_string_lossy().to_string(),
                                                    ));
                                                }
                                                deobfuscated_files.push((name, snippet));
                                                continue;
                                            }

                                            if is_obf
                                                && std::fs::write(&js_path, snippet.as_bytes())
                                                    .is_ok()
                                            {
                                                progress(AnalysisProgress {
                                                    step: format!(
                                                        "Deobfuscating snippet {} with Synchrony...",
                                                        idx + 1
                                                    ),
                                                    fraction: 0.85,
                                                });
                                                if let Ok((code, cleaned_path_opt)) =
                                                    run_synchrony_capture(&js_path)
                                                {
                                                    let cleaned_path =
                                                        cleaned_path_opt.clone().unwrap_or_else(
                                                            || cleaned_js_path(&js_path),
                                                        );
                                                    if cleaned_path_opt.is_none() {
                                                        let _ = std::fs::write(
                                                            &cleaned_path,
                                                            code.as_bytes(),
                                                        );
                                                    }
                                                    let cleaned_name = cleaned_path
                                                        .file_name()
                                                        .unwrap_or_default()
                                                        .to_string_lossy()
                                                        .to_string();
                                                    deobfuscated_file_locations.push((
                                                        cleaned_name.clone(),
                                                        cleaned_path.to_string_lossy().to_string(),
                                                    ));
                                                    deobfuscated_files.push((cleaned_name, code));
                                                } else {
                                                    deobfuscated_file_locations.push((
                                                        name.clone(),
                                                        js_path.to_string_lossy().to_string(),
                                                    ));
                                                    deobfuscated_files.push((name, snippet));
                                                }
                                            } else {
                                                if std::fs::write(&js_path, snippet.as_bytes())
                                                    .is_ok()
                                                {
                                                    deobfuscated_file_locations.push((
                                                        name.clone(),
                                                        js_path.to_string_lossy().to_string(),
                                                    ));
                                                }
                                                deobfuscated_files.push((name, snippet));
                                            }
                                        }
                                    }
                                }

                                for (idx, (name, content)) in extracted.into_iter().enumerate() {
                                    progress(AnalysisProgress {
                                        step: format!("Analyzing extracted JS: {}...", name),
                                        fraction: 0.85,
                                    });
                                    if idx >= 200 {
                                        warnings.push(
                                            "pkg: too many js files, truncated extraction"
                                                .to_string(),
                                        );
                                        break;
                                    }
                                    let safe_name = name
                                        .chars()
                                        .map(|c| {
                                            if c.is_ascii_alphanumeric()
                                                || c == '.'
                                                || c == '_'
                                                || c == '-'
                                            {
                                                c
                                            } else {
                                                '_'
                                            }
                                        })
                                        .collect::<String>();

                                    let js_path = out_dir.join(format!("{idx:03}_{safe_name}"));
                                    let is_obf = detect_js_obfuscation(&content);
                                    js_obfuscated |= is_obf;
                                    merge_strings(
                                        &mut strings,
                                        extract_ascii_strings(content.as_bytes(), 6, 200),
                                        3000,
                                    );

                                    if is_obf && !sync_avail {
                                        need_sync_install = true;
                                        if std::fs::write(&js_path, content.as_bytes()).is_ok() {
                                            deobfuscated_file_locations.push((
                                                name.clone(),
                                                js_path.to_string_lossy().to_string(),
                                            ));
                                        }
                                        deobfuscated_files.push((name, content));
                                        continue;
                                    }

                                    if is_obf
                                        && std::fs::write(&js_path, content.as_bytes()).is_ok()
                                    {
                                        progress(AnalysisProgress {
                                            step: format!(
                                                "Deobfuscating {} with Synchrony...",
                                                name
                                            ),
                                            fraction: 0.85,
                                        });
                                        match run_synchrony_capture(&js_path) {
                                            Ok((code, cleaned_path_opt)) => {
                                                let cleaned_path = cleaned_path_opt
                                                    .clone()
                                                    .unwrap_or_else(|| cleaned_js_path(&js_path));
                                                if cleaned_path_opt.is_none() {
                                                    let _ = std::fs::write(
                                                        &cleaned_path,
                                                        code.as_bytes(),
                                                    );
                                                }
                                                let cleaned_name = cleaned_path
                                                    .file_name()
                                                    .unwrap_or_default()
                                                    .to_string_lossy()
                                                    .to_string();
                                                deobfuscated_file_locations.push((
                                                    cleaned_name.clone(),
                                                    cleaned_path.to_string_lossy().to_string(),
                                                ));
                                                deobfuscated_files.push((cleaned_name, code));
                                            }
                                            Err(_) => {
                                                deobfuscated_file_locations.push((
                                                    name.clone(),
                                                    js_path.to_string_lossy().to_string(),
                                                ));
                                                deobfuscated_files.push((name, content))
                                            }
                                        }
                                    } else {
                                        if std::fs::write(&js_path, content.as_bytes()).is_ok() {
                                            deobfuscated_file_locations.push((
                                                name.clone(),
                                                js_path.to_string_lossy().to_string(),
                                            ));
                                        }
                                        deobfuscated_files.push((name, content));
                                    }
                                }

                                if need_sync_install {
                                    let tm = ToolManager::global();
                                    tm.ensure_tools_available();
                                    warnings.push("JS obfuscation detected; installing synchrony (deobfuscator). Re-analyze once installation is finished.".to_string());
                                }
                            }
                            Err(e) => {
                                warnings.push(format!("pkg prelude parse error: {e:#}"));
                            }
                        }

                        break;
                    }

                    if !found_payload {
                        warnings.push("pkg: PAYLOAD_POSITION definition not found".to_string());
                    }
                }

                let has_external_asar = path.parent().is_some_and(|parent| {
                    parent.join("resources").join("app.asar").exists()
                        || parent.join("resources").join("default_app.asar").exists()
                        || parent.join("app.asar").exists()
                });
                let likely_embedded_asar = fast_contains(bytes, b"{\"files\":");

                // Fallback: If 7-Zip is available, we can try to treat it as Electron if we find specific strings,
                // or if we are desperate (e.g. user insists).
                // For now, let's add a more generous string check for Electron markers.
                let electron_strings: &[&[u8]] = &[
                    b"Electron Framework",
                    b"app.asar",
                    b"node.dll",
                    b"chrome_100_percent.pak",
                    b"chrome_200_percent.pak",
                    b"v8_context_snapshot.bin",
                    b"NullsoftInst", // NSIS Installer signature (often wraps Electron)
                ];
                let likely_electron_strings =
                    electron_strings.iter().any(|s| fast_contains(bytes, s));

                let is_numbered_variant = detect_numbered_electron_variant(path);
                if is_numbered_variant {
                    warnings.push(
                        "Detected 'Numbered/Split' Electron variant (obfuscated structure)"
                            .to_string(),
                    );
                }

                let should_try_electron = matches!(js_container.as_deref(), Some("electron"))
                    || has_external_asar
                    || (deobfuscated_files.is_empty()
                        && (likely_embedded_asar
                            || likely_electron_strings
                            || is_numbered_variant));

                if should_try_electron {
                    let pre_detected =
                        matches!(js_container.as_deref(), Some("electron")) || is_numbered_variant;
                    if let Err(e) = electron_extract_asar_and_sources(
                        path,
                        &work_dir,
                        &mut deobfuscated_files,
                        &mut deobfuscated_file_locations,
                        &mut strings,
                        &mut js_obfuscated,
                        &mut external,
                        &mut warnings,
                        progress,
                        &mut js_files,
                    ) {
                        warnings.push(format!("electron: pipeline error: {e:#}"));
                    }
                    if pre_detected || !deobfuscated_files.is_empty() {
                        js_container = Some("electron".to_string());
                    }
                }

                // Generic 7-Zip fallback for PE files (installers, self-extracting archives)
                // This catches cases where Electron detection failed or it's a non-standard installer
                if deobfuscated_files.is_empty() {
                    // Use the shared work_dir
                    if let Ok(Some(extracted_asar)) =
                        attempt_7zip_fallback(path, &work_dir, &mut warnings)
                    {
                        // If we found an ASAR via generic fallback, try to extract it
                        warnings.push(format!(
                            "Found embedded ASAR via generic 7-Zip fallback: {}",
                            extracted_asar.display()
                        ));
                        let unpack_dir = work_dir.join("asar_unpacked");
                        if let Ok(out) = run_npx_asar_extract(&extracted_asar, &unpack_dir) {
                            if out.exit_code.unwrap_or(1) == 0 {
                                external.push(out);
                                // Recursively scan unpacked ASAR
                                let mut all_files = Vec::new();
                                if collect_files_recursive(&unpack_dir, &mut all_files).is_ok() {
                                    let new_js_files = all_files
                                        .into_iter()
                                        .filter(|p| {
                                            p.extension().map_or(false, |e| {
                                                matches!(
                                                    e.to_ascii_lowercase().to_str().unwrap_or(""),
                                                    "js" | "mjs" | "cjs"
                                                )
                                            })
                                        })
                                        .filter(|p| {
                                            !p.components().any(|c| {
                                                c.as_os_str().eq_ignore_ascii_case("node_modules")
                                            })
                                        })
                                        .collect::<Vec<_>>();

                                    // Process found JS files
                                    for p in new_js_files {
                                        if let Ok(data) = std::fs::read(&p) {
                                            if let Ok(text) = String::from_utf8(data) {
                                                let name = try_relativize(&unpack_dir, &p);
                                                deobfuscated_files.push((name.clone(), text));
                                                deobfuscated_file_locations
                                                    .push((name, p.to_string_lossy().to_string()));
                                            }
                                        }
                                    }
                                    if !deobfuscated_files.is_empty() {
                                        js_container = Some("electron".to_string());
                                    }
                                }
                            }
                        }
                    } else {
                        // If 7-zip extracted files but NO ASAR found, we should still check for JS files directly
                        // attempt_7zip_fallback cleans up, so we need to check the dir manually if it returned None
                        let extract_dir = work_dir.join("7z_extracted");
                        if extract_dir.exists() {
                            let mut all_files = Vec::new();
                            if collect_files_recursive(&extract_dir, &mut all_files).is_ok()
                                && !all_files.is_empty()
                            {
                                warnings.push(format!(
                                    "Generic 7-Zip extraction found {} files (no ASAR)",
                                    all_files.len()
                                ));

                                for p in all_files {
                                    if p.extension().map_or(false, |e| {
                                        matches!(
                                            e.to_ascii_lowercase().to_str().unwrap_or(""),
                                            "js" | "mjs" | "cjs"
                                        )
                                    }) {
                                        if let Ok(data) = std::fs::read(&p) {
                                            if let Ok(text) = String::from_utf8(data) {
                                                let name = try_relativize(&extract_dir, &p);
                                                deobfuscated_files.push((name.clone(), text));
                                                deobfuscated_file_locations
                                                    .push((name, p.to_string_lossy().to_string()));
                                            }
                                        }
                                    }
                                }
                                if !deobfuscated_files.is_empty() {
                                    js_container = Some("electron (installer)".to_string());
                                }
                            }
                        }
                    }
                }

                if cfg!(windows) {
                    candidates.push((
                        "dumpbin",
                        vec![OsString::from("/headers"), p.as_os_str().to_os_string()],
                    ));
                }
                candidates.push((
                    "llvm-objdump",
                    vec![
                        OsString::from("-f"),
                        OsString::from("-h"),
                        p.as_os_str().to_os_string(),
                    ],
                ));
                candidates.push((
                    "objdump",
                    vec![
                        OsString::from("-f"),
                        OsString::from("-h"),
                        p.as_os_str().to_os_string(),
                    ],
                ));
                let (mut outs, mut w) =
                    run_first_available_tool(&candidates, Duration::from_secs(10)); // Increased timeout for synchrony
                external.append(&mut outs);
                warnings.append(&mut w);

                "PE".to_string()
            }
            Object::Elf(elf) => {
                entry_point = Some(elf.entry);
                for (idx, sh) in elf.section_headers.iter().enumerate() {
                    let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
                    sections.push(SectionInfo {
                        name,
                        virtual_address: Some(sh.sh_addr),
                        virtual_size: Some(sh.sh_size),
                        file_offset: Some(sh.sh_offset),
                        file_size: Some(sh.sh_size),
                    });
                    if idx == 0 {
                        let _ = idx;
                    }
                }

                if let Some(cs) = capstone_for_elf(&elf) {
                    if let Some((code, base_addr)) = elf_text_slice_for_entry(&elf, bytes) {
                        disassembly = disassemble(&cs, code, base_addr, 500).unwrap_or_else(|e| {
                            warnings.push(format!("disassembly: {e:#}"));
                            Vec::new()
                        });
                    } else {
                        warnings.push("section .text not found for disassembly".to_string());
                    }
                } else {
                    warnings.push("unsupported ELF architecture for disassembly".to_string());
                }
                let p = path.to_path_buf();
                let candidates: Vec<(&str, Vec<OsString>)> = vec![
                    (
                        "readelf",
                        vec![
                            OsString::from("-h"),
                            OsString::from("-S"),
                            p.as_os_str().to_os_string(),
                        ],
                    ),
                    (
                        "llvm-objdump",
                        vec![
                            OsString::from("-f"),
                            OsString::from("-h"),
                            p.as_os_str().to_os_string(),
                        ],
                    ),
                    (
                        "objdump",
                        vec![
                            OsString::from("-f"),
                            OsString::from("-h"),
                            p.as_os_str().to_os_string(),
                        ],
                    ),
                ];
                let (mut outs, mut w) =
                    run_first_available_tool(&candidates, Duration::from_secs(3));
                external.append(&mut outs);
                warnings.append(&mut w);

                "ELF".to_string()
            }
            Object::Mach(mach) => {
                let (sections_out, ep, disasm, warn) = analyze_mach(bytes, &mach);
                sections = sections_out;
                entry_point = ep;
                disassembly = disasm;
                warnings.extend(warn);
                "Mach-O".to_string()
            }
            other => format!("{other:?}"),
        };

        if let Some(lua_ver) = detect_embedded_lua(&strings) {
            kind = format!("{} ({})", kind, lua_ver);
            language = lua_ver;
        }

        if js_container.is_some() && deobfuscated_files.is_empty() {
            let snippets = carve_probable_js_snippets(bytes);
            if !snippets.is_empty() {
                for (idx, snippet) in snippets.into_iter().enumerate() {
                    let name = format!("carved_binary_snippet_{idx:02}.js");
                    let is_obf = detect_js_obfuscation(&snippet);
                    js_obfuscated |= is_obf;
                    merge_strings(
                        &mut strings,
                        extract_ascii_strings(snippet.as_bytes(), 6, 200),
                        3000,
                    );
                    deobfuscated_files.push((name, snippet));
                }
            }
        }

        if js_obfuscated && !synchrony_available() {
            let tm = ToolManager::global();
            tm.ensure_tools_available();
            warnings.push("JS obfuscation detected; installing synchrony (deobfuscator). Re-analyze once installation is finished.".to_string());
        }

        progress(AnalysisProgress {
            step: "Finalizing analysis".to_string(),
            fraction: 1.0,
        });

        // Detect encryption keys and try to decrypt BEFORE collecting secrets
        let encryption_layer_info = layered_analysis::detect_encryption_keys(bytes, path);
        if let Some((_, Some((desc, data)))) = &encryption_layer_info {
            if let Ok(s) = String::from_utf8(data.clone()) {
                deobfuscated_files.push((desc.clone(), s));
            }
        }

        let secrets = collect_secrets(
            &strings,
            &deobfuscated_files,
            &js_files,
            &disassembly,
            &external,
        );

        // Layered Analysis Report
        let mut report = LayeredAnalysisReport::new(path.to_string_lossy().to_string());
        report.final_payload_type = kind.clone();

        // 1. Container/Obfuscation Check (JS Container in Binary)
        if let Some(container_type) = &js_container {
            report.add_layer(layered_analysis::Layer {
                layer_type: layered_analysis::LayerType::Container,
                method: format!("JS Container ({})", container_type),
                confidence: 100,
                details: format!("Detected embedded JavaScript container: {}", container_type),
                guide: "JS Container detected. Check 'Deobfuscated Files' for extracted content."
                    .to_string(),
                extracted_files: deobfuscated_file_locations
                    .iter()
                    .map(|(_, p)| p.clone())
                    .collect(),
            });
        }

        // 2. Entropy Check
        if let Some(layer) = layered_analysis::detect_high_entropy(bytes) {
            report.add_layer(layer);
        }

        // 3. Encryption Key Check
        if let Some((mut layer, _)) = encryption_layer_info {
            layer.extracted_files = deobfuscated_file_locations
                .iter()
                .map(|(_, p)| p.clone())
                .collect();
            report.add_layer(layer);
        }

        // 4. Extracted File Obfuscation Check (Deep Scan)
        for (name, content) in &deobfuscated_files {
            let is_pkg = matches!(js_container.as_deref(), Some("pkg"));
            if let Some(mut layer) = layered_analysis::detect_js_obfuscation(content, is_pkg) {
                layer.method = format!("{} (in {})", layer.method, name);
                // Attach file path if available
                if let Some((_, path)) = deobfuscated_file_locations.iter().find(|(n, _)| n == name)
                {
                    layer.extracted_files.push(path.clone());
                }
                report.add_layer(layer);
            }
        }

        let mut result = AnalysisResult {
            file_path: path.to_path_buf(),
            file_size: bytes.len() as u64,
            file_format: kind.clone(),
            language,
            kind,
            entry_point,
            python_entrypoint: None,
            imports,
            sections,
            strings,
            disassembly,
            external,
            warnings,
            deobfuscated_files,
            deobfuscated_file_locations: deobfuscated_file_locations.clone(),
            js_files,
            js_container,
            js_obfuscated,
            is_stealer: false,
            secrets,
            confidence_score: 0,
            extracted_dir: None,
            yara_matches: Vec::new(),
            layered_report: Some(report),
        };
        result.confidence_score = calculate_confidence_score(&result);
        Ok(result)
    }
}

fn pe_code_slice_for_rva<'a>(
    pe: &goblin::pe::PE<'a>,
    bytes: &'a [u8],
    rva: u32,
) -> Option<(&'a [u8], u64)> {
    for s in &pe.sections {
        let va = s.virtual_address;
        let vs = s.virtual_size.max(s.size_of_raw_data);
        if rva >= va && rva < va.saturating_add(vs) {
            let delta = rva - va;
            let file_off = s.pointer_to_raw_data.saturating_add(delta) as usize;
            if file_off >= bytes.len() {
                return None;
            }
            let max_len = 4096usize.min(bytes.len() - file_off);
            let base_addr = pe.image_base as u64 + rva as u64;
            return Some((&bytes[file_off..file_off + max_len], base_addr));
        }
    }
    None
}

fn elf_text_slice_for_entry<'a>(
    elf: &goblin::elf::Elf,
    bytes: &'a [u8],
) -> Option<(&'a [u8], u64)> {
    let mut text = None;
    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        if name == ".text" {
            text = Some(sh);
            break;
        }
    }
    let sh = text?;
    let file_off = sh.sh_offset as usize;
    if file_off >= bytes.len() {
        return None;
    }
    let max_len = (sh.sh_size as usize).min(bytes.len() - file_off).min(4096);
    let mut start = 0usize;
    if elf.entry >= sh.sh_addr && elf.entry < sh.sh_addr.saturating_add(sh.sh_size) {
        start = (elf.entry - sh.sh_addr) as usize;
        start = start.min(max_len);
    }
    let code = &bytes[file_off + start..file_off + max_len];
    let base_addr = sh.sh_addr + start as u64;
    Some((code, base_addr))
}

fn analyze_mach(
    bytes: &[u8],
    mach: &goblin::mach::Mach,
) -> (
    Vec<SectionInfo>,
    Option<u64>,
    Vec<InstructionLine>,
    Vec<String>,
) {
    match mach {
        goblin::mach::Mach::Binary(macho) => analyze_macho_binary(bytes, macho),
        goblin::mach::Mach::Fat(_) => (
            Vec::new(),
            None,
            Vec::new(),
            vec!["Mach-O fat: not supported yet".to_string()],
        ),
    }
}

fn analyze_macho_binary(
    bytes: &[u8],
    macho: &goblin::mach::MachO,
) -> (
    Vec<SectionInfo>,
    Option<u64>,
    Vec<InstructionLine>,
    Vec<String>,
) {
    let mut warnings = Vec::new();
    let mut sections = Vec::new();
    let mut entry_point = None::<u64>;
    let mut disassembly = Vec::new();

    for seg in &macho.segments {
        if let Ok(sects) = seg.sections() {
            for (sect, _data) in sects {
                sections.push(SectionInfo {
                    name: format!(
                        "{},{}",
                        sect.segname().unwrap_or(""),
                        sect.name().unwrap_or("")
                    ),
                    virtual_address: Some(sect.addr),
                    virtual_size: Some(sect.size),
                    file_offset: Some(sect.offset as u64),
                    file_size: Some(sect.size),
                });
            }
        }
    }

    let cputype = macho.header.cputype();
    let cs = match cputype {
        0x01000007 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .build()
            .ok(),
        7 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .syntax(arch::x86::ArchSyntax::Intel)
            .build()
            .ok(),
        0x0100000c => Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .build()
            .ok(),
        12 => Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Arm)
            .build()
            .ok(),
        _ => None,
    };

    let Some(cs) = cs else {
        warnings.push("unsupported Mach-O architecture for disassembly".to_string());
        return (sections, entry_point, disassembly, warnings);
    };

    let mut text_section = None::<(u64, u64, u64)>;
    for seg in &macho.segments {
        if let Ok(sects) = seg.sections() {
            for (sect, _data) in sects {
                let segname = sect.segname().unwrap_or("");
                let sectname = sect.name().unwrap_or("");
                if segname == "__TEXT" && sectname == "__text" {
                    text_section = Some((sect.addr, sect.size, sect.offset as u64));
                    break;
                }
            }
        }
    }

    if let Some((addr, size, offset)) = text_section {
        if (offset as usize) < bytes.len() {
            let file_off = offset as usize;
            let max_len = (size as usize).min(bytes.len() - file_off).min(4096);
            let code = &bytes[file_off..file_off + max_len];
            disassembly = disassemble(&cs, code, addr, 500).unwrap_or_else(|e| {
                warnings.push(format!("disassembly: {e:#}"));
                Vec::new()
            });
            entry_point = Some(addr);
        }
    } else {
        warnings.push("section __TEXT,__text not found for disassembly".to_string());
    }

    (sections, entry_point, disassembly, warnings)
}

fn clean_oneshot_header(content: &str) -> String {
    let lines = content.lines();
    let mut kept_lines = Vec::new();
    let mut skipping = true;

    for line in lines {
        if skipping {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let lower = trimmed.to_lowercase();
            // Skip lines that look like OneShot headers (comments or empty lines with specific keywords)
            if trimmed.starts_with('#')
                && (lower.contains("pyarmor")
                    || lower.contains("1-shot")
                    || lower.contains("github.com")
                    || lower.contains("lil-house"))
            {
                continue;
            }
            skipping = false;
        }
        kept_lines.push(line);
    }

    kept_lines.join("\n")
}

fn has_pyarmor_v8_marker(content: &[u8]) -> bool {
    if content.len() < 8 {
        return false;
    }
    for i in 0..=content.len() - 8 {
        if content[i] == b'P'
            && content[i + 1] == b'Y'
            && content[i + 2].is_ascii_digit()
            && content[i + 3].is_ascii_digit()
            && content[i + 4].is_ascii_digit()
            && content[i + 5].is_ascii_digit()
            && content[i + 6].is_ascii_digit()
            && content[i + 7].is_ascii_digit()
        {
            return true;
        }
    }
    false
}

pub struct PyArmorAnalyzer;

impl Analyzer for PyArmorAnalyzer {
    fn name(&self) -> &'static str {
        "pyarmor"
    }

    fn can_handle(&self, _path: &Path, bytes: &[u8]) -> bool {
        // Quick check for PyArmor signatures
        // 1. "pytransform" string often present in older versions
        // 2. "__armor_enter__" function name
        // 3. "PyArmor" header in some versions
        let check_window = bytes.len().min(8192); // Check first 8KB for headers/imports
        let head = &bytes[..check_window];

        let signatures = [
            b"pytransform".as_slice(),
            b"__armor_enter__".as_slice(),
            b"PYARMOR".as_slice(),
        ];

        for sig in signatures {
            if head.windows(sig.len()).any(|w| w == sig) {
                return true;
            }
        }

        // Deep scan for strings if not found in header (fallback)
        let strings = extract_ascii_strings(bytes, 4, 100);
        for s in strings {
            if s.contains("pytransform") || s.contains("__armor_enter__") {
                return true;
            }
        }

        false
    }

    fn analyze(&self, path: &Path, bytes: &[u8]) -> Result<AnalysisResult> {
        let mut warnings = Vec::new();
        let mut external = Vec::new();
        let mut deobfuscated_files = Vec::new();
        let mut deobfuscated_file_locations = Vec::new();

        let _progress_fn = |p: AnalysisProgress| {
            // Local progress handler if needed
            let _ = p;
        };

        // Extract basic strings first
        let strings = extract_ascii_strings(bytes, 4, 3000);

        // Check for Python environment
        let python_cmd = if cfg!(windows) { "python" } else { "python3" };
        if !is_command_available(python_cmd) {
            warnings.push(
                "Python not found. PyArmor deobfuscation requires a valid Python installation."
                    .to_string(),
            );
            return Ok(AnalysisResult {
                file_path: path.to_path_buf(),
                file_size: bytes.len() as u64,
                file_format: "PyArmor (Obfuscated)".to_string(),
                language: "Python".to_string(),
                kind: "PyArmor Obfuscated Script".to_string(),
                entry_point: None,
                python_entrypoint: None,
                imports: Vec::new(),
                sections: Vec::new(),
                strings,
                disassembly: Vec::new(),
                external,
                warnings,
                deobfuscated_files,
                deobfuscated_file_locations,
                js_files: Vec::new(),
                js_container: None,
                js_obfuscated: false,
                is_stealer: false,
                secrets: Vec::new(),
                confidence_score: 10,
                extracted_dir: None,
                yara_matches: Vec::new(),
                layered_report: None,
            });
        }

        // Ensure PyArmor tool is installed
        let tm = ToolManager::global();
        if !tm.is_pyarmor_oneshot_available() {
            log!("PyArmor OneShot tool not available. Triggering installation.");
            tm.ensure_tools_available();
            warnings.push(
                "PyArmor detected; installing unpacker. Re-analyze once installation is finished."
                    .to_string(),
            );
        } else {
            log!("PyArmor OneShot tool found.");
            // Ensure it's fully set up (e.g. scripts extracted) if it was just the exe check
            if let Err(e) = tm.setup_pyarmor_oneshot() {
                warnings.push(format!("Failed to verify PyArmor unpacker: {e}"));
            }
        }

        // Prepare output directory
        let base_name = path.file_name().unwrap_or_default().to_string_lossy();
        let extraction_root = ToolManager::global().get_extracted_dir();
        let _ = std::fs::create_dir_all(&extraction_root);
        let out_dir = extraction_root.join(format!("{base_name}_pyarmor_dump"));
        if out_dir.exists() {
            let _ = std::fs::remove_dir_all(&out_dir);
        }
        std::fs::create_dir_all(&out_dir)?;

        // Run wrapper only if tool is available
        if tm.is_pyarmor_oneshot_available() {
            // Locate the wrapper script
            let tool_path = tm.get_tools_dir().join("pyarmor_wrapper.py");

            if !tool_path.exists() {
                warnings.push(format!("PyArmor wrapper tool not found at {:?}", tool_path));
            } else {
                log!("Running PyArmor wrapper: {:?}", tool_path);
                let input_dir = path.parent().unwrap_or_else(|| Path::new("."));
                let output = std::process::Command::new(python_cmd)
                    .arg(&tool_path)
                    .arg(input_dir)
                    .arg(&out_dir)
                    .creation_flags(0x08000000) // CREATE_NO_WINDOW
                    .output();

                match output {
                    Ok(out) => {
                        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                        let stderr = String::from_utf8_lossy(&out.stderr).to_string();

                        log!("Wrapper finished. Exit code: {:?}", out.status.code());
                        if !stderr.is_empty() {
                            log!("Wrapper stderr: {}", stderr);
                        }

                        external.push(ExternalToolOutput {
                            tool: "pyarmor_wrapper".to_string(),
                            exit_code: out.status.code(),
                            stdout: stdout.clone(),
                            stderr: stderr.clone(),
                        });

                        if out.status.success() {
                            // Scan for files in output directory
                            if let Ok(entries) = std::fs::read_dir(&out_dir) {
                                for entry in entries.flatten() {
                                    let p = entry.path();
                                    let name = p
                                        .file_name()
                                        .unwrap_or_default()
                                        .to_string_lossy()
                                        .to_string();

                                    if name.ends_with(".log") {
                                        continue;
                                    }

                                    let mut clean_name = name.clone();
                                    clean_name = clean_name.replace(".1shot", "");
                                    clean_name = clean_name.replace(".cdc", "");
                                    clean_name = clean_name.replace(".das", ".disasm");
                                    if clean_name.ends_with(".pyc.py") {
                                        clean_name = clean_name.replace(".pyc.py", ".py");
                                    }

                                    if p.extension().map(|e| e == "pyc").unwrap_or(false) {
                                        if let Ok(data) = std::fs::read(&p) {
                                            if let Ok(disasm) =
                                                disassemble::disassemble_python_blob(&data, None)
                                            {
                                                deobfuscated_files.push((
                                                    format!("{}.disasm", clean_name),
                                                    disasm,
                                                ));
                                            }
                                            deobfuscated_file_locations.push((
                                                clean_name,
                                                p.to_string_lossy().to_string(),
                                            ));
                                        }
                                    } else if let Ok(content) = std::fs::read_to_string(&p) {
                                        let cleaned_content = clean_oneshot_header(&content);
                                        deobfuscated_files
                                            .push((clean_name.clone(), cleaned_content));
                                        deobfuscated_file_locations
                                            .push((clean_name, p.to_string_lossy().to_string()));
                                    }
                                }
                            }
                        } else {
                            warnings.push(format!(
                                "PyArmor wrapper failed with code {:?}",
                                out.status.code()
                            ));
                        }
                    }
                    Err(e) => {
                        log!("Failed to execute wrapper: {}", e);
                        warnings.push(format!("Failed to execute PyArmor wrapper: {}", e));
                    }
                }
            }
        } else {
            log!("Skipping wrapper execution because tool is not available yet.");
        }

        // Detect encryption keys and try to decrypt BEFORE collecting secrets
        let encryption_layer_info = layered_analysis::detect_encryption_keys(bytes, path);
        if let Some((_, Some((desc, data)))) = &encryption_layer_info {
            if let Ok(s) = String::from_utf8(data.clone()) {
                deobfuscated_files.push((desc.clone(), s));
            }
        }

        let secrets = collect_secrets(&strings, &deobfuscated_files, &[], &[], &external);

        Ok(AnalysisResult {
            file_path: path.to_path_buf(),
            file_size: bytes.len() as u64,
            file_format: "PyArmor (Obfuscated)".to_string(),
            language: "Python".to_string(),
            kind: "PyArmor Obfuscated Script".to_string(),
            entry_point: None,
            python_entrypoint: None,
            imports: Vec::new(),
            sections: Vec::new(),
            strings,
            disassembly: Vec::new(),
            external,
            warnings,
            deobfuscated_files,
            deobfuscated_file_locations: deobfuscated_file_locations.clone(),
            js_files: Vec::new(),
            js_container: None,
            js_obfuscated: false,
            is_stealer: false,
            secrets,
            confidence_score: 10,
            extracted_dir: Some(out_dir),
            yara_matches: Vec::new(),
            layered_report: {
                let mut report = LayeredAnalysisReport::new(path.to_string_lossy().to_string());
                report.final_payload_type = "Python Source/Bytecode".to_string();

                // 1. PyArmor Layer (Confirmed by Analyzer)
                let has_pyarmor7 = bytes.windows(7).any(|w| w == b"PYARMOR");
                let has_pyarmor8 = has_pyarmor_v8_marker(bytes);

                let guide = if has_pyarmor7 && !has_pyarmor8 {
                    "PyArmor version <= 7 detected. One Shot tool does not support this version."
                        .to_string()
                } else {
                    "PyArmor detected. Automatic deobfuscation with One Shot attempted.".to_string()
                };

                report.add_layer(layered_analysis::Layer {
                    layer_type: layered_analysis::LayerType::Obfuscation,
                    method: "PyArmor".to_string(),
                    confidence: 100,
                    details: "File matched PyArmor signatures.".to_string(),
                    guide,
                    extracted_files: deobfuscated_file_locations
                        .iter()
                        .map(|(_, p)| p.clone())
                        .collect(),
                });

                if let Some(layer) = layered_analysis::detect_high_entropy(bytes) {
                    report.add_layer(layer);
                }

                if let Some((layer, _)) = encryption_layer_info {
                    report.add_layer(layer);
                }

                Some(report)
            },
        })
    }
}

pub struct PyInstallerExeAnalyzer;

fn analyze_pyinstaller_exe(
    path: &Path,
    bytes: &[u8],
    progress: &mut dyn FnMut(AnalysisProgress),
) -> Result<AnalysisResult> {
    progress(AnalysisProgress {
        step: "Analyzing PyInstaller archive structure...".to_string(),
        fraction: 0.02,
    });

    let mut warnings = Vec::new();
    let mut external = Vec::new();
    let mut deobfuscated_files = Vec::new();
    let mut deobfuscated_file_locations = Vec::new();
    let mut stealer_layers = Vec::new();

    let mut file_format = "Unknown".to_string();
    let mut imports = Vec::new();
    match Object::parse(bytes) {
        Ok(Object::PE(pe)) => {
            file_format = "PE".to_string();
            imports = pe_imports(&pe);
        }
        Ok(Object::Elf(_)) => file_format = "ELF".to_string(),
        Ok(Object::Mach(_)) => file_format = "Mach-O".to_string(),
        Ok(other) => file_format = format!("{other:?}"),
        Err(_) => {}
    }

    progress(AnalysisProgress {
        step: "Extracting PyInstaller metadata...".to_string(),
        fraction: 0.08,
    });

    let archive = extractor::parse_pyinstaller_archive(bytes)?;
    let pyver = Some((archive.py_major, archive.py_minor));
    let entrypoints = extractor::pyinstaller_entry_points(&archive);
    let chosen = extractor::pyinstaller_pick_entrypoint(&entrypoints);

    external.push(ExternalToolOutput {
        tool: "pyinstaller".to_string(),
        exit_code: None,
        stdout: format!(
            "Python version: {}.{}\nEntrypoint: {}\nPossible entry points:\n{}",
            archive.py_major,
            archive.py_minor,
            chosen.clone().unwrap_or_else(|| "-".to_string()),
            entrypoints
                .iter()
                .map(|e| format!("  - {e}"))
                .collect::<Vec<_>>()
                .join("\n")
        ),
        stderr: String::new(),
    });

    progress(AnalysisProgress {
        step: "Identifying entry points...".to_string(),
        fraction: 0.14,
    });

    if entrypoints.is_empty() {
        if let Ok(Some((module, text))) =
            extractor::pyinstaller_try_disassemble_from_pyz(&archive, bytes, pyver, None)
        {
            external.push(ExternalToolOutput {
                tool: "python-dis".to_string(),
                exit_code: None,
                stdout: format!("Module: {module}\n\n{text}"),
                stderr: String::new(),
            });
        } else {
            warnings.push("no entry point found in PyInstaller archive".to_string());
        }
    } else {
        let pysource = extractor::pyinstaller_extract_pysource(&archive, bytes)?;
        let wanted = chosen.as_ref().unwrap_or(&entrypoints[0]);
        if let Some((_, raw)) = pysource.iter().find(|(n, _)| n == wanted) {
            let res = disassemble::disassemble_python_blob(raw, pyver)
                .or_else(|e1| disassemble::disassemble_python_blob(raw, None).map_err(|_| e1));
            match res {
                Ok(text) => external.push(ExternalToolOutput {
                    tool: "python-dis".to_string(),
                    exit_code: None,
                    stdout: format!("File: {wanted}\n\n{text}"),
                    stderr: String::new(),
                }),
                Err(e) => {
                    if let Ok(Some((module, text))) =
                        extractor::pyinstaller_try_disassemble_from_pyz(
                            &archive,
                            bytes,
                            pyver,
                            Some(wanted),
                        )
                    {
                        external.push(ExternalToolOutput {
                            tool: "python-dis".to_string(),
                            exit_code: None,
                            stdout: format!("File: {wanted}\nModule: {module}\n\n{text}"),
                            stderr: String::new(),
                        });
                    } else {
                        let head_hex = raw
                            .iter()
                            .take(32)
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(" ");
                        warnings.push(format!(
                            "pyc disassembly failed: {e:#} | First 32 bytes: {head_hex}"
                        ));
                    }
                }
            }
        } else if let Ok(Some((module, text))) =
            extractor::pyinstaller_try_disassemble_from_pyz(&archive, bytes, pyver, Some(wanted))
        {
            external.push(ExternalToolOutput {
                tool: "python-dis".to_string(),
                exit_code: None,
                stdout: format!("File: {wanted}\nModule: {module}\n\n{text}"),
                stderr: String::new(),
            });
        } else {
            warnings.push(format!(
                "entry point payload not found in archive after parsing: {wanted}"
            ));
        }
    }

    progress(AnalysisProgress {
        step: "PyInstaller: extracting .pyc / PYZ".to_string(),
        fraction: 0.22,
    });

    fn looks_like_pyc(bytes: &[u8]) -> bool {
        bytes.len() >= 4 && bytes[2] == 0x0d && bytes[3] == 0x0a
    }

    fn build_pyc_header(pyver: Option<(u8, u8)>, magic: Option<[u8; 4]>) -> Vec<u8> {
        let magic = magic.unwrap_or([0u8; 4]);
        let mut out = Vec::new();
        out.extend_from_slice(&magic);
        match pyver {
            Some((maj, min)) if maj > 3 || (maj == 3 && min >= 7) => {
                out.extend_from_slice(&[0u8; 4]);
                out.extend_from_slice(&[0u8; 8]);
            }
            Some((maj, min)) if maj > 3 || (maj == 3 && min >= 3) => {
                out.extend_from_slice(&[0u8; 4]);
                out.extend_from_slice(&[0u8; 4]);
            }
            _ => {
                out.extend_from_slice(&[0u8; 4]);
            }
        }
        out
    }

    let base_name = path.file_name().unwrap_or_default().to_string_lossy();
    let extraction_root = ToolManager::global().get_extracted_dir();
    let _ = std::fs::create_dir_all(&extraction_root);
    let out_dir = extraction_root.join(format!("{base_name}_extracted"));

    let mut found_stealer = false;

    let pyc_magic = extractor::pyinstaller_best_pyc_magic(&archive, bytes)
        .ok()
        .flatten();

    let mut disassembled_for_ui = 0usize;
    let max_disassembled_for_ui = 120usize;
    let max_disassembly_text_bytes = 2 * 1024 * 1024;
    let mut disassembly_truncated = false;

    let mut written = 0usize;
    let mut write_failures = 0usize;
    let mut used_external_extractor = false;
    if out_dir.exists() {
        let _ = std::fs::remove_dir_all(&out_dir);
    }

    if let Ok(tool) = ensure_pyinstxtractor_ng(progress) {
        progress(AnalysisProgress {
            step: "PyInstaller: extracting with pyinstxtractor-ng".to_string(),
            fraction: 0.24,
        });

        if let Ok(out) = run_pyinstxtractor_ng(&tool, path, &extraction_root) {
            used_external_extractor = out.exit_code == Some(0);
            external.push(out);
        }
    }

    if !used_external_extractor {
        warnings.push("pyinstxtractor-ng failed, fallback to internal extractor".to_string());

        let extracted_entries = extractor::pyinstaller_extract_all_entries(&archive, bytes)?;
        let extracted_entry_count = extracted_entries.len();
        let total_items = extracted_entry_count.max(1);
        let mut pyz_files = 0usize;
        let mut pyz_modules = 0usize;
        let mut pyz_encrypted = 0usize;

        for (idx, ent) in extracted_entries.into_iter().enumerate() {
            let frac = 0.22 + 0.78 * ((idx + 1) as f32 / total_items as f32);
            progress(AnalysisProgress {
                step: format!("Extracting file {}/{}", idx + 1, total_items),
                fraction: frac.min(0.999),
            });

            let rel = extractor::sanitize_rel_path(&ent.name);
            let dst = out_dir.join(rel);
            if let Some(parent) = dst.parent()
                && std::fs::create_dir_all(parent).is_err()
            {
                write_failures = write_failures.saturating_add(1);
                continue;
            }

            if std::fs::write(&dst, &ent.payload).is_ok() {
                written = written.saturating_add(1);
            } else {
                write_failures = write_failures.saturating_add(1);
            }

            if ent.type_code == b'z' || ent.type_code == b'Z' {
                pyz_files = pyz_files.saturating_add(1);
                match extractor::pyinstaller_extract_pyz_modules_named(
                    &ent.name,
                    &ent.payload,
                    pyver,
                ) {
                    Ok(mods) => {
                        pyz_modules = pyz_modules.saturating_add(mods.len());
                        for m in mods {
                            if m.encrypted {
                                pyz_encrypted = pyz_encrypted.saturating_add(1);
                            }
                            let rel = extractor::sanitize_rel_path(&m.name);
                            let dst = out_dir.join(rel);
                            if let Some(parent) = dst.parent() {
                                let _ = std::fs::create_dir_all(parent);
                            }
                            let mut out_bytes = Vec::new();
                            if m.encrypted || looks_like_pyc(&m.payload) {
                                out_bytes.extend_from_slice(&m.payload);
                            } else if m.name.ends_with(".pyc") {
                                out_bytes.extend_from_slice(&build_pyc_header(pyver, pyc_magic));
                                out_bytes.extend_from_slice(&m.payload);
                            } else {
                                out_bytes.extend_from_slice(&m.payload);
                            }
                            if std::fs::write(&dst, &out_bytes).is_ok() {
                                written = written.saturating_add(1);
                            } else {
                                write_failures = write_failures.saturating_add(1);
                            }
                        }
                    }
                    Err(e) => warnings.push(format!("pyinstaller: pyz extraction failed: {e:#}")),
                }
            }
        }

        external.push(ExternalToolOutput {
            tool: "pyinstaller-extract".to_string(),
            exit_code: None,
            stdout: format!(
                "CArchive: {total_items} file(s)\nPYZ: {pyz_files} archive(s), {pyz_modules} module(s), {pyz_encrypted} encrypted/non-zlib"
            ),
            stderr: String::new(),
        });
    }

    let mut all_files = Vec::new();
    if out_dir.exists() {
        let _ = collect_files_recursive(&out_dir, &mut all_files);
        let mut pyc_files = all_files
            .clone()
            .into_iter()
            .filter(|p| {
                p.extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case("pyc"))
            })
            .collect::<Vec<_>>();
        pyc_files.sort_by(|a, b| {
            let is_pyz_related = |path: &std::path::PathBuf| -> bool {
                let s = path.to_string_lossy().to_ascii_lowercase();
                if s.contains(".pyz_extracted") {
                    return true;
                }
                for comp in path.components() {
                    let c = comp.as_os_str().to_string_lossy();
                    if c.eq_ignore_ascii_case("pyz") {
                        return true;
                    }
                }
                false
            };

            let a_pyz = is_pyz_related(a);
            let b_pyz = is_pyz_related(b);

            if a_pyz != b_pyz {
                // False (non-pyz) < True (pyz), so non-pyz comes first
                return a_pyz.cmp(&b_pyz);
            }
            a.cmp(b)
        });

        let total_pyc = pyc_files.len();
        for (idx, p) in pyc_files.into_iter().enumerate() {
            if idx % 5 == 0 {
                let current_frac = 0.24 + 0.75 * ((idx + 1) as f32 / total_pyc.max(1) as f32);
                progress(AnalysisProgress {
                    step: format!("Analyzing extracted file {}/{}", idx + 1, total_pyc),
                    fraction: current_frac.min(0.99),
                });
            }

            if disassembled_for_ui >= max_disassembled_for_ui {
                disassembly_truncated = true;
                break;
            }

            let payload = match std::fs::read(&p) {
                Ok(b) => b,
                Err(_) => {
                    write_failures = write_failures.saturating_add(1);
                    continue;
                }
            };

            let dis = disassemble::disassemble_python_blob(&payload, pyver)
                .or_else(|e1| disassemble::disassemble_python_blob(&payload, None).map_err(|_| e1));
            let mut text = match dis {
                Ok(t) => t,
                Err(e) => format!("pyc disassembly failed: {e:#}"),
            };
            if text.len() > max_disassembly_text_bytes {
                text.truncate(max_disassembly_text_bytes);
            }

            let rel = try_relativize(&out_dir, &p).replace('\\', "/");
            let name = format!("{rel}.dis.txt");
            let dis_path = PathBuf::from(format!("{}.dis.txt", p.to_string_lossy()));
            if std::fs::write(&dis_path, text.as_bytes()).is_ok() {
                deobfuscated_file_locations
                    .push((name.clone(), dis_path.to_string_lossy().to_string()));
            } else {
                deobfuscated_file_locations.push((name.clone(), String::new()));
            }
            deobfuscated_files.push((name.clone(), text.clone()));
            disassembled_for_ui = disassembled_for_ui.saturating_add(1);

            let fname = p.file_name().unwrap_or_default().to_string_lossy();
            let p_str = p.to_string_lossy();
            // Optimization: Skip heuristic scan for standard libraries to avoid "infinite loop" perception
            let is_lib = fname.starts_with("pyi_")
                || fname.starts_with("pyimod")
                || p_str.contains("Crypto")
                || p_str.contains("encodings")
                || p_str.contains("ctypes")
                || p_str.contains("xml")
                || p_str.contains("http")
                || p_str.contains("urllib")
                || p_str.contains("site-packages")
                || p_str.contains("distutils")
                || p_str.contains("multiprocessing")
                || p_str.contains("unittest");

            let mut scan_res = crate::heuristic_decryptor::ScanResult::default();

            if !is_lib {
                log!("Checking {} for heuristic scan...", fname);
                scan_res = crate::heuristic_decryptor::scan_text(&text);

                // Link Decryptor Text Scan (Fallback/Parallel)
                // [DISABLED] Manual trigger only to reduce latency
                /*
                let text_links = crate::link_decryptor::scan_disassembly_text(&text);
                if !text_links.is_empty() {
                    let content = text_links.join("\n");
                    let link_name = format!("{}_text_decrypted_links.txt", fname);
                    deobfuscated_files.push((link_name, content));
                    log!("Link Decryptor (Text Scan) found {} potential links in {}", text_links.len(), fname);
                }
                */

                match disassemble::parse_code_object(&payload) {
                    Ok(code_obj) => {
                        let code_scan = crate::heuristic_decryptor::scan_code_object(&code_obj);
                        crate::heuristic_decryptor::merge_scan_results(&mut scan_res, code_scan);

                        // Link Decryptor Integration
                        // [DISABLED] Manual trigger only to reduce latency
                        /*
                        let links = crate::link_decryptor::scan_and_decrypt_links(&code_obj);
                        if !links.is_empty() {
                            let content = links.join("\n");
                            let link_name = format!("{}_decrypted_links.txt", fname);
                            deobfuscated_files.push((link_name, content));
                            log!("Link Decryptor found {} potential links in {}", links.len(), fname);
                        }
                        */
                    }
                    Err(e) => {
                        log!("Failed to parse code object for {}: {}", fname, e);
                    }
                }

                // Fallback: Scan raw bytes as text
                let raw_strings = String::from_utf8_lossy(&payload);
                let raw_scan = crate::heuristic_decryptor::scan_text(&raw_strings);
                crate::heuristic_decryptor::merge_scan_results(&mut scan_res, raw_scan);
                log!(
                    "Scanned {}: {} keys, {} files",
                    fname,
                    scan_res.potential_keys.len(),
                    scan_res.potential_files.len()
                );
            }

            if !scan_res.potential_keys.is_empty() || !scan_res.potential_files.is_empty() {
                let debug_info = format!(
                    "Scanning {}: Found {} keys, {} files",
                    name,
                    scan_res.potential_keys.len(),
                    scan_res.potential_files.len()
                );
                log!("Heuristic Scan: {}", debug_info);
                external.push(ExternalToolOutput {
                    tool: "heuristic_scan_debug".to_string(),
                    exit_code: None,
                    stdout: debug_info,
                    stderr: String::new(),
                });

                let stealer_res =
                    crate::malware::stealer::attempt_decrypt_stealer_aes(&scan_res, &out_dir);
                if stealer_res.is_some() {
                    found_stealer = true;
                }
                let dec_res = stealer_res.or_else(|| {
                    crate::heuristic_decryptor::attempt_decryption(&scan_res, &out_dir)
                });
                if let Some((desc, data)) = dec_res {
                    // Only flag as Stealer if it was actually detected as such via specific artifacts
                    // found_stealer = true; // Removed unconditional flag
                    let safe_desc = desc.replace(" ", "_").replace("(", "").replace(")", "");

                    log!(
                        "Heuristic Success: Decrypted {} ({} bytes)",
                        desc,
                        data.len()
                    ); // Added file logging
                    external.push(ExternalToolOutput {
                        tool: "heuristic_decrypt_success".to_string(),
                        exit_code: None,
                        stdout: format!("Successfully decrypted: {} ({} bytes)", desc, data.len()),
                        stderr: String::new(),
                    });

                    // Scan for PE header (MZ) even if not at start (common in shellcodes/loaders)
                    let mut data_to_write = data.clone();
                    let mut found_pe = false;

                    // Check if it's already a PE at offset 0
                    if data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A {
                        found_pe = true;
                    } else {
                        // Quick scan in first 4KB
                        let scan_limit = std::cmp::min(data.len(), 4096);
                        for i in 0..scan_limit.saturating_sub(1) {
                            if data[i] == 0x4D && data[i + 1] == 0x5A {
                                // Potential PE start, check if it looks valid
                                // e_lfanew at 0x3C relative to i
                                if data.len() >= i + 0x40 {
                                    let offset_bytes = &data[i + 0x3C..i + 0x40];
                                    let pe_offset =
                                        u32::from_le_bytes(offset_bytes.try_into().unwrap())
                                            as usize;
                                    if data.len() >= i + pe_offset + 4 {
                                        if &data[i + pe_offset..i + pe_offset + 4] == b"PE\0\0" {
                                            // Confirmed PE
                                            log!(
                                                "[Heuristic] Found embedded PE header at offset {}, trimming...",
                                                i
                                            );
                                            data_to_write = data[i..].to_vec();
                                            found_pe = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Determine extension using robust type detection
                    let mut detected_type =
                        crate::detect_type_file::detect_type_from_bytes(&data_to_write);

                    // Handle Gzip/Zlib decompression if detected
                    let mut decompressed_ok = false;

                    if detected_type.contains("Gzip") {
                        log!("[Heuristic] Detected Gzip archive, attempting decompression...");
                        if let Ok(decompressed) = decompress_gzip(&data_to_write) {
                            log!(
                                "[Heuristic] Gzip decompression successful ({} bytes -> {} bytes)",
                                data_to_write.len(),
                                decompressed.len()
                            );
                            data_to_write = decompressed;
                            decompressed_ok = true;
                        } else {
                            log!("[Heuristic] Gzip decompression failed");
                        }
                    } else if detected_type.contains("Zlib") {
                        log!("[Heuristic] Detected Zlib archive, attempting decompression...");
                        if let Ok(decompressed) = decompress_zlib(&data_to_write) {
                            log!(
                                "[Heuristic] Zlib decompression successful ({} bytes -> {} bytes)",
                                data_to_write.len(),
                                decompressed.len()
                            );
                            data_to_write = decompressed;
                            decompressed_ok = true;
                        } else {
                            log!("[Heuristic] Zlib decompression failed");
                        }
                    } else if detected_type == "Unknown" && data_to_write.len() > 2 {
                        // Fallback: Check for Zlib headers manually if type is Unknown
                        if data_to_write[0] == 0x78
                            && (data_to_write[1] == 0x01
                                || data_to_write[1] == 0x9C
                                || data_to_write[1] == 0xDA)
                        {
                            log!(
                                "[Heuristic] Detected potential Zlib header in Unknown file, attempting decompression..."
                            );
                            if let Ok(decompressed) = decompress_zlib(&data_to_write) {
                                log!(
                                    "[Heuristic] Fallback Zlib decompression successful ({} bytes -> {} bytes)",
                                    data_to_write.len(),
                                    decompressed.len()
                                );
                                data_to_write = decompressed;
                                decompressed_ok = true;
                            }
                        }
                    }

                    if decompressed_ok {
                        // Re-detect type on decompressed data
                        detected_type =
                            crate::detect_type_file::detect_type_from_bytes(&data_to_write);
                        // Re-scan for PE header
                        if data_to_write.len() >= 2
                            && data_to_write[0] == 0x4D
                            && data_to_write[1] == 0x5A
                        {
                            found_pe = true;
                        } else {
                            // Deep scan for PE header in decompressed data
                            let scan_limit = std::cmp::min(data_to_write.len(), 4096);
                            for i in 0..scan_limit.saturating_sub(1) {
                                if data_to_write[i] == 0x4D && data_to_write[i + 1] == 0x5A {
                                    if data_to_write.len() >= i + 0x40 {
                                        let offset_bytes = &data_to_write[i + 0x3C..i + 0x40];
                                        let pe_offset =
                                            u32::from_le_bytes(offset_bytes.try_into().unwrap())
                                                as usize;
                                        if data_to_write.len() >= i + pe_offset + 4 {
                                            if &data_to_write[i + pe_offset..i + pe_offset + 4]
                                                == b"PE\0\0"
                                            {
                                                log!(
                                                    "[Heuristic] Found embedded PE header in decompressed data at offset {}, trimming...",
                                                    i
                                                );
                                                data_to_write = data_to_write[i..].to_vec();
                                                found_pe = true;
                                                // Update detected type after trimming
                                                detected_type =
                                                    crate::detect_type_file::detect_type_from_bytes(
                                                        &data_to_write,
                                                    );
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    log!(
                        "[Heuristic] Detected type: {} (Has MZ: {})",
                        detected_type,
                        found_pe
                    );
                    let (ext, is_exe) = if found_pe
                        || detected_type.contains("EXE")
                        || detected_type.contains("Executable")
                        || detected_type.contains("PE")
                    {
                        (".exe", true)
                    } else if detected_type.contains("DLL") {
                        (".dll", true)
                    } else if detected_type.contains("ZIP") {
                        (".zip", false)
                    } else if detected_type.contains("ELF") {
                        (".elf", true)
                    } else if data.len() >= 4 && data[0] == 0x55 && data[1] == 0x0d {
                        (".pyc", false)
                    } else if crate::disassemble::parse_code_object(&data).is_ok() {
                        (".pyc", false)
                    } else if std::str::from_utf8(&data).is_ok() {
                        (".txt", false)
                    } else {
                        (".bin", false)
                    };

                    let decrypted_dir = if is_exe {
                        out_dir.join("Extracted Exe")
                    } else {
                        out_dir.join("Decrypted")
                    };
                    let _ = std::fs::create_dir_all(&decrypted_dir);

                    let out_name = if is_exe {
                        format!("payload_decrypted{}", ext)
                    } else {
                        format!("decrypted_{}{}", safe_desc, ext)
                    };

                    let out_path = decrypted_dir.join(&out_name);
                    let mut target_dir = decrypted_dir.clone();
                    let mut wrote = false;

                    if std::fs::write(&out_path, &data_to_write).is_ok() {
                        deobfuscated_file_locations.push((
                            format!(
                                "{}/{}",
                                if is_exe { "Extracted Exe" } else { "Decrypted" },
                                out_name
                            ),
                            out_path.to_string_lossy().to_string(),
                        ));
                        wrote = true;
                    } else if let Some(parent_dir) = out_dir.parent() {
                        // Fallback
                        let fallback_dir = parent_dir.join("Decrypted");
                        let _ = std::fs::create_dir_all(&fallback_dir);
                        let fallback_path = fallback_dir.join(&out_name);
                        if std::fs::write(&fallback_path, &data_to_write).is_ok() {
                            deobfuscated_file_locations.push((
                                format!("Decrypted/{}", out_name),
                                fallback_path.to_string_lossy().to_string(),
                            ));
                            target_dir = fallback_dir;
                            wrote = true;
                        }
                    }

                    // Use folder prefix for UI grouping
                    let ui_folder = if is_exe {
                        "Extracted Exe/"
                    } else {
                        "Decrypted/"
                    };

                    // If data looks like text/url, show it
                    if let Ok(s) = String::from_utf8(data_to_write.clone()) {
                        deobfuscated_files.push((format!("{}{}.txt", ui_folder, safe_desc), s));
                    } else {
                        // Binary data
                        deobfuscated_files.push((
                            format!("{}{}", ui_folder, out_name),
                            format!(
                                "Binary data ({} bytes) - Type: {}",
                                data_to_write.len(),
                                detected_type
                            ),
                        ));
                    }

                    // Extract strings from decrypted binary/pyc
                    if wrote && (ext == ".pyc" || ext == ".bin") {
                        let strs = extract_ascii_strings(&data_to_write, 4, 3000);
                        if !strs.is_empty() {
                            let strings_content = strs.join("\n");
                            let strings_name = format!("{}{}_strings.txt", ui_folder, safe_desc);
                            let strings_disk_name = format!("decrypted_{}_strings.txt", safe_desc);
                            let strings_path = target_dir.join(&strings_disk_name);

                            if std::fs::write(&strings_path, &strings_content).is_ok() {
                                deobfuscated_file_locations.push((
                                    strings_name.clone(),
                                    strings_path.to_string_lossy().to_string(),
                                ));
                            }
                            deobfuscated_files.push((strings_name, strings_content));
                        }
                    }

                    if let Ok(_code) = disassemble::parse_code_object(&data_to_write) {
                        if let Ok(dis) = disassemble::disassemble_python_blob(&data_to_write, None)
                        {
                            deobfuscated_files
                                .push((format!("{}{}.dis.txt", ui_folder, safe_desc), dis));
                        }
                    }

                    let artifacts = crate::malware::stealer::extract_stealer_artifacts(
                        &data_to_write,
                        &out_dir,
                        pyver,
                    );
                    if !artifacts.layers.is_empty() {
                        stealer_layers.extend(artifacts.layers);
                    }
                    if !artifacts.files.is_empty() || !artifacts.file_locations.is_empty() {
                        deobfuscated_files.extend(artifacts.files);
                        deobfuscated_file_locations.extend(artifacts.file_locations);
                    }
                } else {
                    let fail_msg = format!(
                        "Failed to decrypt {} despite finding keys. Check if dependent files exist in {}",
                        name,
                        out_dir.display()
                    );
                    log!("Heuristic Fail: {}", fail_msg);
                    external.push(ExternalToolOutput {
                        tool: "heuristic_decrypt_fail".to_string(),
                        exit_code: None,
                        stdout: fail_msg,
                        stderr: String::new(),
                    });
                }
            }
        }
    }

    if disassembly_truncated {
        warnings.push(format!(
            "pyinstaller: disassembly truncated (UI limit = {max_disassembled_for_ui})"
        ));
    }

    external.push(ExternalToolOutput {
        tool: "pyinstaller-pyc-dump".to_string(),
        exit_code: None,
        stdout: format!(
            "Folder: {}\nFiles written: {written}\nFailures: {write_failures}",
            out_dir.to_string_lossy()
        ),
        stderr: String::new(),
    });
    warnings.push(format!(
        "pyinstaller: files extracted to {}",
        out_dir.to_string_lossy()
    ));

    // Scan for obfuscated payloads (lzma/zlib) in extracted files
    let mut new_deobfuscated_files = Vec::new();
    for (name, content) in &deobfuscated_files {
        let payloads = deobfuscator::scan_and_decompress_payloads(content);
        for (method, data) in payloads {
            log!("Found obfuscated payload in {} using {}", name, method);
            // Prefix with LZMA_ZLIB/ so the UI can group them
            let mut new_name = format!("LZMA_ZLIB/{}.extracted_{}", name, method);

            // Try to disassemble if it looks like python bytecode
            let dis = disassemble::disassemble_python_blob(&data, pyver)
                .or_else(|_| disassemble::disassemble_python_blob(&data, None));

            if let Ok(text) = dis {
                new_name.push_str(".dis.txt");
                new_deobfuscated_files.push((new_name.clone(), text));
            } else {
                // Not valid bytecode, maybe source or just data?
                if let Ok(s) = String::from_utf8(data.clone()) {
                    new_name.push_str(".txt");
                    new_deobfuscated_files.push((new_name.clone(), s));
                } else {
                    new_name.push_str(".bin");
                    new_deobfuscated_files.push((
                        new_name.clone(),
                        format!("Binary data ({} bytes)", data.len()),
                    ));
                }
            }

            deobfuscated_file_locations.push((new_name.clone(), String::new()));
        }
    }
    deobfuscated_files.extend(new_deobfuscated_files);

    // Scan for Stealer Stub in extracted files (direct stub-o.pyc or similar)
    let mut stub_artifacts_files = Vec::new();
    let mut stub_artifacts_locations = Vec::new();
    let mut processed_stubs = BTreeSet::new();

    // Helper to process a potential stub file
    let mut process_stub_file = |p: &Path| {
        println!("DEBUG: Checking potential stub file: {:?}", p);
        let p_str = p.to_string_lossy().to_string();
        if processed_stubs.contains(&p_str) {
            println!("DEBUG: Already processed: {:?}", p);
            return;
        }
        processed_stubs.insert(p_str);

        if let Ok(bytes) = std::fs::read(p) {
            println!("DEBUG: Read {} bytes from stub file", bytes.len());
            if let Some(parent) = p.parent() {
                let artifacts = crate::malware::stealer::extract_stub_sources_from_pyc(p, parent);
                if !artifacts.files.is_empty() {
                    println!("DEBUG: Extracted {} files from stub", artifacts.files.len());
                    stub_artifacts_files.extend(artifacts.files);
                    stub_artifacts_locations.extend(artifacts.file_locations);
                    found_stealer = true;
                    log!("Extracted stub sources from {:?}", p);
                } else {
                    println!("DEBUG: No artifacts extracted from stub");
                }
            }
        } else {
            println!("DEBUG: Failed to read stub file");
        }
    };

    // 1. Scan known deobfuscated locations
    println!(
        "DEBUG: Scanning deobfuscated_file_locations for stubs (count: {})",
        deobfuscated_file_locations.len()
    );
    for (_name, path_str) in &deobfuscated_file_locations {
        if !path_str.is_empty() {
            let p = Path::new(path_str);
            let file_name = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            if file_name.to_ascii_lowercase().contains("stub")
                && file_name.to_ascii_lowercase().ends_with(".pyc")
            {
                // Avoid re-processing stubs that were already handled by extract_stealer_artifacts
                // The Stealer module creates a "Stealer" directory and handles extraction internally.
                if path_str.contains("Stealer") {
                    continue;
                }
                process_stub_file(p);
            }
        }
    }

    // 2. Scan the extraction directory (out_dir) for stub-o.pyc if it exists
    if out_dir.exists() {
        println!("DEBUG: Scanning out_dir for stubs: {:?}", out_dir);
        for entry in walkdir::WalkDir::new(&out_dir)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let p = entry.path();
            if p.is_file() {
                let file_name = p
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                if file_name.to_ascii_lowercase().contains("stub")
                    && file_name.to_ascii_lowercase().ends_with(".pyc")
                {
                    if p.to_string_lossy().contains("Stealer") {
                        continue;
                    }
                    println!("DEBUG: Found candidate stub file: {:?}", p);
                    process_stub_file(p);
                }
            }
        }
    } else {
        println!("DEBUG: out_dir does not exist: {:?}", out_dir);
    }

    deobfuscated_files.extend(stub_artifacts_files);
    deobfuscated_file_locations.extend(stub_artifacts_locations);

    // Check for PyArmor in extracted files
    let mut pyarmor_detected = false;
    for (name, _) in &deobfuscated_file_locations {
        if name.to_lowercase().contains("pytransform") || name.to_lowercase().contains("pyarmor") {
            pyarmor_detected = true;
            break;
        }
    }
    if !pyarmor_detected {
        for (_, content) in &deobfuscated_files {
            if content.contains("pytransform") || content.contains("PY000000") {
                pyarmor_detected = true;
                break;
            }
        }
    }

    if pyarmor_detected {
        log!("PyArmor detected in extracted files.");
        let tm = ToolManager::global();

        // Ensure PyArmor OneShot is fully set up (including wrapper script)
        let _ = tm.setup_pyarmor_oneshot();

        if !tm.is_pyarmor_oneshot_available() {
            log!("PyArmor OneShot tool not available. Triggering installation.");
            tm.ensure_tools_available();
            warnings.push("PyArmor detected in extracted files; installing unpacker. Re-analyze once installation is finished.".to_string());
        } else {
            log!("PyArmor OneShot tool found.");

            let tools_dir = ToolManager::global().get_tools_dir();
            let oneshot_exe = tools_dir.join("pyarmor-1shot").join("pyarmor-1shot.exe");

            if oneshot_exe.exists() {
                log!("Using PyArmor OneShot executable: {:?}", oneshot_exe);

                let mut targets = Vec::new();
                for p in &all_files {
                    let p_str = p.to_string_lossy().to_lowercase();
                    let fname = p
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_lowercase();

                    if p.extension().map(|s| s == "pyc").unwrap_or(false) {
                        // Skip PYZ contents as they are likely standard library/dependencies
                        if p_str.contains(".pyz_extracted") {
                            continue;
                        }

                        // Skip PyInstaller runtime files and standard libs
                        if fname.starts_with("pyi_")
                            || fname.starts_with("pyimod")
                            || fname == "struct.pyc"
                        {
                            continue;
                        }

                        // Check content for PyArmor markers
                        if let Ok(content) = std::fs::read(p) {
                            // Simple byte sequence check
                            let haystack = String::from_utf8_lossy(&content);
                            if haystack.contains("PY000000")
                                || haystack.contains("__pyarmor__")
                                || haystack.contains("PYARMOR")
                                || haystack.contains("pytransform")
                            {
                                log!("Found PyArmor marker in: {:?}", p);
                                targets.push(p.clone());
                            }
                        }
                    }
                }

                if targets.is_empty() && chosen.is_some() {
                    // Fallback: try to match the chosen file if no explicit markers found (legacy behavior)
                    if let Some(entry) = &chosen {
                        log!(
                            "No explicit PyArmor markers found. Trying chosen entry point: {}",
                            entry
                        );
                        for p in &all_files {
                            if p.file_stem().map(|s| s == entry.as_str()).unwrap_or(false)
                                && p.extension().map(|s| s == "pyc").unwrap_or(false)
                            {
                                if p.to_string_lossy()
                                    .to_lowercase()
                                    .contains(".pyz_extracted")
                                {
                                    continue;
                                }
                                targets.push(p.clone());
                                break;
                            }
                        }
                    }
                } else {
                    log!("Found {} confirmed PyArmor targets.", targets.len());
                }

                for target in targets {
                    log!("Processing target: {:?}", target);

                    // Ensure target is compatible with OneShot.
                    // Error "Unknown 1-shot sequence indicator 6F" matches Py3.10 Magic (0x6F 0x0D).
                    // This suggests OneShot expects a HEADERLESS marshal dump (raw code object).
                    if let Ok(content) = std::fs::read(&target) {
                        let has_pyarmor7 = content.windows(7).any(|w| w == b"PYARMOR");
                        let has_pyarmor8 = has_pyarmor_v8_marker(&content);
                        if has_pyarmor7 && !has_pyarmor8 {
                            let msg = format!(
                                "PyArmor <=7 detected in {} (marker PYARMOR). OneShot supports PyArmor 8+ only.",
                                target.file_name().unwrap_or_default().to_string_lossy()
                            );
                            log!("{}", msg);
                            warnings.push(msg.clone());
                            external.push(ExternalToolOutput {
                                tool: "pyarmor-1shot".to_string(),
                                exit_code: Some(1),
                                stdout: String::new(),
                                stderr: msg,
                            });
                            continue;
                        }
                        let mut needs_strip = false;
                        if content.len() > 16 {
                            // Check for common Python magic numbers (Little Endian)
                            // Standard .pyc files have \r\n (0x0D 0x0A) at offset 2 and 3.
                            if content[2] == 0x0d && content[3] == 0x0a {
                                needs_strip = true;
                            } else if (content[0] == 0x6f && content[1] == 0x0d)
                                || (content[0] == 0xa7 && content[1] == 0x0d)
                                || (content[0] == 0x61 && content[1] == 0x0d)
                                || (content[0] == 0x55 && content[1] == 0x0d)
                                || (content[0] == 0x42 && content[1] == 0x0d)
                                || (content[0] == 0xcb && content[1] == 0x0d)
                            {
                                // Py3.12
                                needs_strip = true;
                            }
                        }

                        if needs_strip {
                            log!(
                                "Header detected (Magic {:02x} {:02x}). Stripping 16-byte header for OneShot.",
                                content[0],
                                content[1]
                            );
                            let mut new_content = content[16..].to_vec();

                            // Fix for TYPE_CODE with FLAG_REF (0xE3) -> TYPE_CODE (0x63)
                            if !new_content.is_empty() && new_content[0] == 0xE3 {
                                log!(
                                    "Detected TYPE_CODE with FLAG_REF (0xE3) in stripped content. Patching to 0x63 for OneShot."
                                );
                                new_content[0] = 0x63;
                            }

                            if let Err(e) = std::fs::write(&target, &new_content) {
                                log!("Failed to write stripped file to {:?}: {}", target, e);
                            } else {
                                // Verify it's a code object (0x63 / 'c')
                                // OneShot expects a marshalled code object.
                                if !new_content.is_empty() && new_content[0] != 0x63 {
                                    log!(
                                        "Warning: Stripped content of {:?} does not start with TYPE_CODE (0x63), but {:02x}. OneShot may fail.",
                                        target,
                                        new_content[0]
                                    );
                                    // If it's a Set (0xE3) or other non-code object, skip OneShot to avoid errors.
                                    continue;
                                }
                            }
                        } else {
                            // No header strip needed, check existing content
                            let mut modified = false;
                            let mut new_content = content.clone();

                            if !new_content.is_empty() && new_content[0] == 0xE3 {
                                log!(
                                    "Detected TYPE_CODE with FLAG_REF (0xE3). Patching to 0x63 for OneShot."
                                );
                                new_content[0] = 0x63;
                                modified = true;
                            }

                            if modified {
                                if let Err(e) = std::fs::write(&target, &new_content) {
                                    log!("Failed to write patched file to {:?}: {}", target, e);
                                }
                            }

                            if !new_content.is_empty() && new_content[0] != 0x63 {
                                log!(
                                    "Warning: Content of {:?} does not start with TYPE_CODE (0x63), but {:02x}. OneShot may fail.",
                                    target,
                                    new_content[0]
                                );
                                continue;
                            }
                        }
                    }

                    let dump_dir = out_dir.join(format!(
                        "{}_pyarmor_dump",
                        target.file_stem().unwrap_or_default().to_string_lossy()
                    ));
                    if dump_dir.exists() {
                        let _ = std::fs::remove_dir_all(&dump_dir);
                    }
                    let _ = std::fs::create_dir_all(&dump_dir);

                    log!("Running OneShot command via wrapper...");
                    let wrapper_path = tools_dir.join("pyarmor_wrapper.py");
                    let python_cmd = if cfg!(target_os = "windows") {
                        "python"
                    } else {
                        "python3"
                    };

                    let output = std::process::Command::new(python_cmd)
                        .arg(&wrapper_path)
                        .arg(&target)
                        .arg(&dump_dir)
                        .creation_flags(0x08000000)
                        .output();

                    match output {
                        Ok(out) => {
                            log!(
                                "OneShot finished. Exit code: {:?}, stdout len: {}, stderr len: {}",
                                out.status.code(),
                                out.stdout.len(),
                                out.stderr.len()
                            );
                            if !out.stdout.is_empty() {
                                log!("STDOUT: {}", String::from_utf8_lossy(&out.stdout));
                            }
                            if !out.stderr.is_empty() {
                                log!("STDERR: {}", String::from_utf8_lossy(&out.stderr));
                            }

                            external.push(ExternalToolOutput {
                                tool: format!(
                                    "pyarmor-1shot ({})",
                                    target.file_name().unwrap_or_default().to_string_lossy()
                                ),
                                exit_code: out.status.code(),
                                stdout: String::from_utf8_lossy(&out.stdout).to_string(),
                                stderr: String::from_utf8_lossy(&out.stderr).to_string(),
                            });

                            if out.status.success() {
                                // Move generated files from source dir to dump_dir
                                if let Some(parent) = target.parent() {
                                    if let Ok(entries) = std::fs::read_dir(parent) {
                                        for entry in entries.flatten() {
                                            let p = entry.path();
                                            let fname =
                                                p.file_name().unwrap_or_default().to_string_lossy();
                                            if fname.contains(".1shot") {
                                                let dest = dump_dir.join(p.file_name().unwrap());
                                                log!("Moving OneShot output {:?} to {:?}", p, dest);
                                                let _ = std::fs::rename(&p, &dest);
                                            }
                                        }
                                    }
                                }

                                log!("OneShot success. Scanning dump dir: {:?}", dump_dir);
                                if let Ok(entries) = std::fs::read_dir(&dump_dir) {
                                    for entry in entries.flatten() {
                                        let p = entry.path();
                                        let name = p
                                            .file_name()
                                            .unwrap_or_default()
                                            .to_string_lossy()
                                            .to_string();

                                        // Skip logs
                                        if name.ends_with(".log") {
                                            continue;
                                        }

                                        log!("Found file in dump: {:?}", p);
                                        if let Ok(content) = std::fs::read_to_string(&p) {
                                            let mut clean_name = name.clone();
                                            // Clean up OneShot artifacts from filename
                                            clean_name = clean_name.replace(".1shot", "");
                                            clean_name = clean_name.replace(".cdc", "");
                                            clean_name = clean_name.replace(".das", ".disasm");

                                            // Fix double extensions if any
                                            if clean_name.ends_with(".pyc.py") {
                                                clean_name = clean_name.replace(".pyc.py", ".py");
                                            }

                                            let cleaned_content = clean_oneshot_header(&content);

                                            // Update the file on disk to remove the header
                                            if let Err(e) = std::fs::write(&p, &cleaned_content) {
                                                log!(
                                                    "Failed to write cleaned content to {:?}: {}",
                                                    p,
                                                    e
                                                );
                                            }

                                            deobfuscated_files
                                                .push((clean_name.clone(), cleaned_content));
                                            // Add location so it appears in the PyArmor folder in UI
                                            deobfuscated_file_locations.push((
                                                clean_name,
                                                p.to_string_lossy().to_string(),
                                            ));
                                        }
                                    }
                                }
                            } else {
                                log!("OneShot returned non-zero exit code.");
                                warnings.push(format!(
                                    "PyArmor OneShot failed for {}. Check External tab.",
                                    target.file_name().unwrap_or_default().to_string_lossy()
                                ));
                            }
                        }
                        Err(e) => {
                            log!(
                                "Failed to execute OneShot command: {} (cmd: {:?})",
                                e,
                                oneshot_exe
                            );
                            warnings.push(format!(
                                "Failed to run PyArmor OneShot: {} (cmd: {:?})",
                                e, oneshot_exe
                            ));
                        }
                    }
                }
            } else {
                log!(
                    "PyArmor OneShot executable not found at: {:?}. Triggering re-installation.",
                    oneshot_exe
                );
                tm.ensure_tools_available();
                warnings.push(
                    "PyArmor OneShot executable not found. Installing... Re-analyze once finished."
                        .to_string(),
                );
            }
        }
    } else {
        log!("No PyArmor detected in extracted files.");
    }

    progress(AnalysisProgress {
        step: "Finalizing PyInstaller analysis...".to_string(),
        fraction: 1.0,
    });

    let strings = extract_ascii_strings(bytes, 4, 3000);
    let secrets = collect_secrets(&strings, &deobfuscated_files, &[], &[], &external);

    let mut result = AnalysisResult {
        file_path: path.to_path_buf(),
        file_size: bytes.len() as u64,
        file_format,
        language: "Python".to_string(),
        kind: "Python executable (PyInstaller)".to_string(),
        entry_point: None,
        python_entrypoint: chosen,
        imports,
        sections: Vec::new(),
        strings,
        disassembly: Vec::new(),
        external,
        warnings,
        deobfuscated_files,
        deobfuscated_file_locations: deobfuscated_file_locations.clone(),
        js_files: Vec::new(),
        js_container: None,
        js_obfuscated: false,
        is_stealer: found_stealer,
        secrets,
        confidence_score: 1,
        extracted_dir: Some(out_dir),
        yara_matches: Vec::new(),
        layered_report: {
            let mut report = LayeredAnalysisReport::new(path.to_string_lossy().to_string());
            report.final_payload_type = "Python Bytecode".to_string();

            // Layer 1: PyInstaller Container
            report.add_layer(layered_analysis::Layer {
                layer_type: layered_analysis::LayerType::Container,
                method: "PyInstaller".to_string(),
                confidence: 100,
                details: format!(
                    "PyInstaller archive (v{}.{})",
                    archive.py_major, archive.py_minor
                ),
                guide: "Use 'pyinstxtractor-ng' (automatic) to extract contents.".to_string(),
                extracted_files: deobfuscated_file_locations
                    .iter()
                    .map(|(_, p)| p.clone())
                    .collect(),
            });

            for layer in stealer_layers {
                report.add_layer(layer);
            }

            if pyarmor_detected {
                report.add_layer(layered_analysis::Layer {
                    layer_type: layered_analysis::LayerType::Obfuscation,
                    method: "PyArmor".to_string(),
                    confidence: 100,
                    details: "PyArmor obfuscation detected in extracted files.".to_string(),
                    guide: "Use 'pyarmor-1shot' (automatic) to unpack.".to_string(),
                    extracted_files: Vec::new(),
                });
            }

            Some(report)
        },
    };
    result.confidence_score = calculate_confidence_score(&result);
    Ok(result)
}

impl Analyzer for PyInstallerExeAnalyzer {
    fn name(&self) -> &'static str {
        "pyinstaller_exe"
    }

    fn can_handle(&self, _path: &Path, bytes: &[u8]) -> bool {
        extractor::looks_like_pyinstaller(bytes)
    }

    fn analyze(&self, path: &Path, bytes: &[u8]) -> Result<AnalysisResult> {
        let mut progress = |_| {};
        analyze_pyinstaller_exe(path, bytes, &mut progress)
    }

    fn analyze_with_progress(
        &self,
        path: &Path,
        bytes: &[u8],
        progress: &mut dyn FnMut(AnalysisProgress),
    ) -> Result<AnalysisResult> {
        analyze_pyinstaller_exe(path, bytes, progress)
    }
}

pub struct SourceTextAnalyzer;

impl Analyzer for SourceTextAnalyzer {
    fn name(&self) -> &'static str {
        "source_text"
    }

    fn can_handle(&self, path: &Path, bytes: &[u8]) -> bool {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        matches!(
            ext.as_str(),
            "py" | "js" | "ts" | "c" | "cc" | "cpp" | "h" | "hpp" | "rs" | "go" | "java"
        ) && std::str::from_utf8(bytes).is_ok()
    }

    fn analyze(&self, path: &Path, bytes: &[u8]) -> Result<AnalysisResult> {
        let mut warnings = Vec::new();
        let mut external = Vec::new();
        let mut deobfuscated_files = Vec::new();
        let mut deobfuscated_file_locations = Vec::new();

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        let language = match ext.as_str() {
            "py" => "Python",
            "js" => "JavaScript",
            "ts" => "TypeScript",
            "c" | "h" => "C",
            "cc" | "cpp" | "hpp" => "C++",
            "rs" => "Rust",
            "go" => "Go",
            "java" => "Java",
            _ => "Source",
        }
        .to_string();

        let preview = std::str::from_utf8(bytes)
            .unwrap_or("")
            .lines()
            .take(2000)
            .collect::<Vec<_>>()
            .join("\n");

        external.push(ExternalToolOutput {
            tool: "preview".to_string(),
            exit_code: None,
            stdout: preview,
            stderr: String::new(),
        });

        let mut js_obfuscated = false;
        if ext == "js" {
            let raw = std::str::from_utf8(bytes).unwrap_or("").to_string();
            js_obfuscated = detect_js_obfuscation(&raw);

            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            if js_obfuscated {
                deobfuscated_file_locations
                    .push((name.clone(), path.to_string_lossy().to_string()));
                deobfuscated_files.push((name.clone(), raw.clone()));
                if synchrony_available() {
                    match run_synchrony_capture(path) {
                        Ok((code, cleaned_path_opt)) => {
                            let cleaned_path = cleaned_path_opt
                                .clone()
                                .unwrap_or_else(|| cleaned_js_path(path));
                            if cleaned_path_opt.is_none() {
                                let _ = std::fs::write(&cleaned_path, code.as_bytes());
                            }
                            let cleaned_name = cleaned_path
                                .file_name()
                                .unwrap_or_default()
                                .to_string_lossy()
                                .to_string();
                            deobfuscated_file_locations.push((
                                cleaned_name.clone(),
                                cleaned_path.to_string_lossy().to_string(),
                            ));
                            deobfuscated_files.push((cleaned_name, code));
                        }
                        Err(e) => {
                            warnings.push(format!("synchrony error: {e:#}"));
                        }
                    }
                } else {
                    let tm = ToolManager::global();
                    tm.ensure_tools_available();
                    warnings.push("JS obfuscation detected; installing synchrony (deobfuscator). Re-analyze once installation is finished.".to_string());
                }
            }
        }

        let strings = extract_ascii_strings(bytes, 4, 3000);

        // Detect encryption keys and try to decrypt BEFORE collecting secrets
        let encryption_layer_info = layered_analysis::detect_encryption_keys(bytes, path);
        if let Some((_, Some((desc, data)))) = &encryption_layer_info {
            if let Ok(s) = String::from_utf8(data.clone()) {
                deobfuscated_files.push((desc.clone(), s));
            }
        }

        let secrets = collect_secrets(&strings, &deobfuscated_files, &[], &[], &external);

        // Layered Analysis
        let mut report = LayeredAnalysisReport::new(path.to_string_lossy().to_string());
        if let Some(layer) = layered_analysis::detect_obfuscation(bytes, false) {
            report.add_layer(layer);
        }
        if let Some(layer) = layered_analysis::detect_base64(bytes) {
            report.add_layer(layer);
        }
        if let Some((layer, _)) = encryption_layer_info {
            report.add_layer(layer);
        }

        let mut result = AnalysisResult {
            file_path: path.to_path_buf(),
            file_size: bytes.len() as u64,
            file_format: "Text".to_string(),
            language,
            kind: "Source".to_string(),
            entry_point: None,
            python_entrypoint: None,
            imports: Vec::new(),
            sections: Vec::new(),
            strings,
            disassembly: Vec::new(),
            external,
            warnings,
            deobfuscated_files,
            deobfuscated_file_locations,
            js_files: Vec::new(),
            js_container: if ext == "js" {
                Some("source".to_string())
            } else {
                None
            },
            js_obfuscated,
            is_stealer: false,
            secrets,
            confidence_score: 0,
            extracted_dir: None,
            yara_matches: Vec::new(),
            layered_report: Some(report),
        };
        result.confidence_score = calculate_confidence_score(&result);
        Ok(result)
    }
}

pub struct PycAnalyzer;

impl Analyzer for PycAnalyzer {
    fn name(&self) -> &'static str {
        "pyc"
    }

    fn can_handle(&self, path: &Path, bytes: &[u8]) -> bool {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        if ext == "pyc" {
            return true;
        }
        bytes.len() >= 4 && bytes[2] == 0x0d && bytes[3] == 0x0a
    }

    fn analyze(&self, path: &Path, bytes: &[u8]) -> Result<AnalysisResult> {
        let mut found_stealer = false;
        let mut warnings = Vec::new();
        let mut external = Vec::new();
        let mut deobfuscated_files = Vec::new();
        let mut deobfuscated_file_locations = Vec::new();
        let mut stealer_layers = Vec::new();

        let header_len = bytes.len().min(16);
        let header_hex = bytes[..header_len]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");

        external.push(ExternalToolOutput {
            tool: "pyc_header".to_string(),
            exit_code: None,
            stdout: format!("header({header_len} bytes): {header_hex}"),
            stderr: String::new(),
        });

        match disassemble::disassemble_python_blob(bytes, None) {
            Ok(text) => external.push(ExternalToolOutput {
                tool: "python-dis".to_string(),
                exit_code: None,
                stdout: text,
                stderr: String::new(),
            }),
            Err(e) => warnings.push(format!("pyc disassembly failed: {e:#}")),
        }

        if let Some(parent) = path.parent() {
            let file_name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            if file_name.to_ascii_lowercase().contains("stub") {
                let artifacts =
                    crate::malware::stealer::extract_stub_sources_from_pyc(path, parent);
                if !artifacts.files.is_empty() || !artifacts.file_locations.is_empty() {
                    found_stealer = true;
                    deobfuscated_files.extend(artifacts.files);
                    deobfuscated_file_locations.extend(artifacts.file_locations);
                }
            }
        }

        // Heuristic Decryption (Stealer / Universal AES)
        let mut scan_res = crate::heuristic_decryptor::ScanResult::default();

        // 1. Try parsing code object
        println!("[PycAnalyzer] Parsing code object...");
        let code_obj_res = disassemble::parse_code_object(bytes);
        if let Err(ref e) = code_obj_res {
            println!("[PycAnalyzer] Parse failed: {}", e);
        }

        // let mut links_found = false;

        if let Ok(code_obj) = code_obj_res {
            println!("[PycAnalyzer] Code object parsed successfully.");
            let obj_scan = crate::heuristic_decryptor::scan_code_object(&code_obj);
            crate::heuristic_decryptor::merge_scan_results(&mut scan_res, obj_scan);

            // Link Decryptor Integration
            // [DISABLED] Manual trigger only
            /*
            let links = crate::link_decryptor::scan_and_decrypt_links(&code_obj);
            if !links.is_empty() {
                let content = links.join("\n");
                deobfuscated_files.push(("Decrypted Links (Link Decryptor)".to_string(), content));
                warnings.push(format!("Link Decryptor found {} potential links", links.len()));
                links_found = true;
            }
            */
        }

        // 2. Try text disassembly (fallback for hard-to-parse pyc)
        let mut disasm_text_opt = disassemble::disassemble_python_blob(bytes, None).ok();

        // Fallback: Check if .dis.txt exists on disk (e.g. from user or previous run)
        if disasm_text_opt.is_none() {
            let path_str = path.to_string_lossy().to_string();
            let dis_path = std::path::Path::new(&path_str).with_file_name(format!(
                "{}.dis.txt",
                path.file_name().unwrap().to_string_lossy()
            ));
            if dis_path.exists() {
                println!(
                    "[PycAnalyzer] Found existing disassembly file: {:?}",
                    dis_path
                );
                if let Ok(content) = std::fs::read_to_string(&dis_path) {
                    disasm_text_opt = Some(content);
                }
            }
        }

        if let Some(disasm_text) = disasm_text_opt {
            println!("[PycAnalyzer] Scanning disassembly text...");
            let text_scan = crate::heuristic_decryptor::scan_text(&disasm_text);
            crate::heuristic_decryptor::merge_scan_results(&mut scan_res, text_scan);

            // Link Decryptor Fallback (Text Scan)
            // [DISABLED] Manual trigger only
            /*
            if !links_found {
                let links = crate::link_decryptor::scan_disassembly_text(&disasm_text);
                if !links.is_empty() {
                    let content = links.join("\n");
                    deobfuscated_files.push(("Decrypted Links (Text Scan)".to_string(), content));
                    warnings.push(format!("Link Decryptor (Text Scan) found {} potential links", links.len()));
                }
            }
            */
        }

        // 3. Try raw string scan
        let raw_strings = String::from_utf8_lossy(bytes);
        let raw_scan = crate::heuristic_decryptor::scan_text(&raw_strings);
        crate::heuristic_decryptor::merge_scan_results(&mut scan_res, raw_scan);

        // 4. Try Python Script Decryptor (Ultimate Fallback / Enhanced Scan)
        {
            // Write current bytes to temp file to ensure we analyze exactly what we have in memory
            let temp_dir = std::env::temp_dir().join("singularity_scan");
            let _ = std::fs::create_dir_all(&temp_dir);
            let temp_path = temp_dir.join(format!(
                "scan_{}.pyc",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis()
            ));

            if std::fs::write(&temp_path, bytes).is_ok() {
                println!("[PycAnalyzer] Running Python Script Decryptor...");
                /* [DISABLED] Manual trigger only
                let py_links = crate::link_decryptor::run_python_decryptor(&temp_path);
                let _ = std::fs::remove_file(&temp_path);

                if !py_links.is_empty() {
                    let content = py_links.join("\n");
                    deobfuscated_files.push(("Decrypted Links (Python Script)".to_string(), content));
                    warnings.push(format!("Python Script Decryptor found {} potential links", py_links.len()));
                }
                */
                let _ = std::fs::remove_file(&temp_path);
            }
        }

        println!(
            "[PycAnalyzer] Scan results: {} keys, {} files",
            scan_res.potential_keys.len(),
            scan_res.potential_files.len()
        );

        // Report potential keys/files in external tool output for visibility
        if !scan_res.potential_keys.is_empty() || !scan_res.potential_files.is_empty() {
            let mut scan_info = String::new();
            scan_info.push_str("Found potential artifacts:\n");
            for f in &scan_res.potential_files {
                scan_info.push_str(&format!("  File: {}\n", f));
            }
            for k in &scan_res.potential_keys {
                scan_info.push_str(&format!("  Key/IV: {} bytes\n", k.len()));
            }
            external.push(ExternalToolOutput {
                tool: "heuristic_scan".to_string(),
                exit_code: None,
                stdout: scan_info,
                stderr: String::new(),
            });

            // Attempt decryption
            if let Some(parent) = path.parent() {
                if let Some((desc, data)) =
                    crate::heuristic_decryptor::attempt_decryption(&scan_res, parent)
                {
                    found_stealer = true;
                    let safe_desc = desc.replace(" ", "_").replace("(", "").replace(")", "");

                    // Write to disk for UI visualization
                    let base_name = path.file_name().unwrap_or_default().to_string_lossy();
                    let extraction_root = ToolManager::global().get_extracted_dir();
                    let _ = std::fs::create_dir_all(&extraction_root);
                    let out_dir = extraction_root.join(format!("{base_name}_extracted"));
                    if std::fs::create_dir_all(&out_dir).is_ok() {
                        // Simple heuristic for extension
                        let ext = if data.len() >= 4 && data[0] == 0x55 && data[1] == 0x0d {
                            ".pyc"
                        } else if crate::disassemble::parse_code_object(&data).is_ok() {
                            ".pyc"
                        } else if std::str::from_utf8(&data).is_ok() {
                            ".txt"
                        } else {
                            ".bin"
                        };

                        let decrypted_dir = out_dir.join("Decrypted");
                        let _ = std::fs::create_dir_all(&decrypted_dir);
                        let out_name = format!("decrypted_{}{}", safe_desc, ext);
                        let out_path = decrypted_dir.join(&out_name);
                        let mut target_dir = decrypted_dir.clone();
                        let mut wrote = false;
                        if std::fs::write(&out_path, &data).is_ok() {
                            deobfuscated_file_locations.push((
                                format!("Decrypted/{}", out_name),
                                out_path.to_string_lossy().to_string(),
                            ));
                            wrote = true;
                        } else if let Some(parent_dir) = out_dir.parent() {
                            let fallback_dir = parent_dir.join("Decrypted");
                            let _ = std::fs::create_dir_all(&fallback_dir);
                            let fallback_path = fallback_dir.join(&out_name);
                            if std::fs::write(&fallback_path, &data).is_ok() {
                                deobfuscated_file_locations.push((
                                    format!("Decrypted/{}", out_name),
                                    fallback_path.to_string_lossy().to_string(),
                                ));
                                target_dir = fallback_dir;
                                wrote = true;
                            }
                        }

                        // Extract strings from decrypted binary/pyc
                        if wrote && (ext == ".pyc" || ext == ".bin") {
                            let strs = extract_ascii_strings(&data, 4, 3000);
                            if !strs.is_empty() {
                                let strings_content = strs.join("\n");
                                let strings_name = format!("decrypted_{}_strings.txt", safe_desc);
                                let strings_path = target_dir.join(&strings_name);
                                if std::fs::write(&strings_path, &strings_content).is_ok() {
                                    deobfuscated_file_locations.push((
                                        format!("Decrypted/{}", strings_name),
                                        strings_path.to_string_lossy().to_string(),
                                    ));
                                }
                            }
                        }
                    }

                    // If data looks like text/url, show it
                    if let Ok(s) = String::from_utf8(data.clone()) {
                        deobfuscated_files.push((format!("decrypted_{}.txt", safe_desc), s));
                    } else {
                        // Binary data
                        deobfuscated_files.push((
                            format!("decrypted_{}.bin", safe_desc),
                            format!("Binary data ({} bytes)", data.len()),
                        ));
                    }

                    // If it's a code object (marshal), try to disassemble it too
                    if let Ok(_code) = disassemble::parse_code_object(&data) {
                        if let Ok(dis) = disassemble::disassemble_python_blob(&data, None) {
                            deobfuscated_files
                                .push((format!("decrypted_{}.dis.txt", safe_desc), dis));
                        }
                    }

                    let artifacts =
                        crate::malware::stealer::extract_stealer_artifacts(&data, &out_dir, None);
                    if !artifacts.layers.is_empty() {
                        stealer_layers.extend(artifacts.layers);
                    }
                    if !artifacts.files.is_empty() || !artifacts.file_locations.is_empty() {
                        found_stealer = true;
                        deobfuscated_files.extend(artifacts.files);
                        deobfuscated_file_locations.extend(artifacts.file_locations);
                    }
                }
            }
        }

        let strings = extract_ascii_strings(bytes, 4, 3000);
        let secrets = collect_secrets(&strings, &deobfuscated_files, &[], &[], &external);

        // Layered Analysis Report
        let mut report = LayeredAnalysisReport::new(path.to_string_lossy().to_string());
        report.final_payload_type = "Python Bytecode".to_string();

        for layer in stealer_layers {
            report.add_layer(layer);
        }

        // 1. Check for Stealer
        if found_stealer {
            report.add_layer(layered_analysis::Layer {
                layer_type: layered_analysis::LayerType::Obfuscation,
                method: "Stealer".to_string(),
                confidence: 100,
                details: "Identified Stealer stub or artifacts.".to_string(),
                guide: "Stealer stub detected. The 'deobfuscated_files' section contains extracted config/source.".to_string(),
                extracted_files: deobfuscated_file_locations.iter().map(|(_, p)| p.clone()).collect(),
            });
        }

        // 2. Check for Heuristic Encryption Keys
        if !scan_res.potential_keys.is_empty() {
            let details = format!(
                "Found {} potential keys, {} IVs",
                scan_res.potential_keys.len(),
                scan_res.potential_ivs.len()
            );
            report.add_layer(layered_analysis::Layer {
                layer_type: layered_analysis::LayerType::Encryption,
                method: "Heuristic Key Discovery".to_string(),
                confidence: 80,
                details,
                guide: "Encryption keys found. Check the 'Heuristic Scan' output or try the 'Heuristic Decryptor' tool.".to_string(),
                extracted_files: Vec::new(),
            });
        }

        // 3. General Obfuscation Check (using disassembled text if available, else raw)
        // We use the first successful disassembly or raw string
        let content_for_check =
            if let Some(output) = external.iter().find(|o| o.tool == "python-dis") {
                output.stdout.as_bytes()
            } else {
                bytes
            };

        if let Some(layer) = layered_analysis::detect_obfuscation(content_for_check, false) {
            report.add_layer(layer);
        }

        // 4. Entropy Check
        if let Some(layer) = layered_analysis::detect_high_entropy(bytes) {
            report.add_layer(layer);
        }

        Ok(AnalysisResult {
            file_path: path.to_path_buf(),
            file_size: bytes.len() as u64,
            file_format: ".pyc".to_string(),
            language: "Python".to_string(),
            kind: "Python bytecode (.pyc)".to_string(),
            entry_point: None,
            python_entrypoint: None,
            imports: Vec::new(),
            sections: Vec::new(),
            strings,
            disassembly: Vec::new(),
            external,
            warnings,
            deobfuscated_files,
            deobfuscated_file_locations,
            js_files: Vec::new(),
            js_container: None,
            js_obfuscated: false,
            is_stealer: found_stealer,
            secrets,
            confidence_score: 80,
            extracted_dir: None,
            yara_matches: Vec::new(),
            layered_report: Some(report),
        })
    }
}

pub struct UnknownAnalyzer;

impl Analyzer for UnknownAnalyzer {
    fn name(&self) -> &'static str {
        "unknown"
    }

    fn can_handle(&self, _path: &Path, _bytes: &[u8]) -> bool {
        true
    }

    fn analyze(&self, path: &Path, bytes: &[u8]) -> Result<AnalysisResult> {
        let strings = extract_ascii_strings(bytes, 4, 3000);

        let mut deobfuscated_files = Vec::new();
        // Detect encryption keys and try to decrypt BEFORE collecting secrets
        let encryption_layer_info = layered_analysis::detect_encryption_keys(bytes, path);
        if let Some((_, Some((desc, data)))) = &encryption_layer_info {
            if let Ok(s) = String::from_utf8(data.clone()) {
                deobfuscated_files.push((desc.clone(), s));
            }
        }

        let secrets = collect_secrets(&strings, &deobfuscated_files, &[], &[], &[]);

        // Layered Analysis
        let mut report = LayeredAnalysisReport::new(path.to_string_lossy().to_string());

        let obf_layer = layered_analysis::detect_obfuscation(bytes, false);
        let entropy_layer = layered_analysis::detect_high_entropy(bytes);
        let base64_layer = layered_analysis::detect_base64(bytes);

        // Prioritize Obfuscation over generic High Entropy Encryption
        if let Some(obf) = obf_layer {
            report.add_layer(obf);
            // If obfuscation is detected, high entropy is expected. Only report if it's Compression.
            if let Some(ent) = entropy_layer {
                if matches!(ent.layer_type, layered_analysis::LayerType::Compression) {
                    report.add_layer(ent);
                }
            }
        } else if let Some(ent) = entropy_layer {
            report.add_layer(ent);
        }

        if let Some(layer) = base64_layer {
            report.add_layer(layer);
        }

        if let Some((layer, _)) = encryption_layer_info {
            report.add_layer(layer);
        }

        Ok(AnalysisResult {
            file_path: path.to_path_buf(),
            file_size: bytes.len() as u64,
            file_format: "Unknown".to_string(),
            language: "Unknown".to_string(),
            kind: "Unsupported".to_string(),
            entry_point: None,
            python_entrypoint: None,
            imports: Vec::new(),
            sections: Vec::new(),
            strings,
            disassembly: Vec::new(),
            external: Vec::new(),
            warnings: vec!["unsupported file type".to_string()],
            deobfuscated_files,
            deobfuscated_file_locations: Vec::new(),
            js_files: Vec::new(),
            js_container: None,
            js_obfuscated: false,
            is_stealer: false,
            secrets,
            confidence_score: 1,
            extracted_dir: None,
            yara_matches: Vec::new(),
            layered_report: Some(report),
        })
    }
}

pub struct LuaAnalyzer;

impl Analyzer for LuaAnalyzer {
    fn name(&self) -> &'static str {
        "lua"
    }

    fn can_handle(&self, path: &Path, bytes: &[u8]) -> bool {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        if ext == "lua" || ext == "luac" {
            return true;
        }
        // Check for Lua bytecode signature: \x1bLua
        if bytes.len() >= 4 && bytes.starts_with(b"\x1bLua") {
            return true;
        }
        // Check for LuaJIT bytecode signature: \x1bLJ
        if bytes.len() >= 3 && bytes.starts_with(b"\x1bLJ") {
            return true;
        }
        false
    }

    fn analyze(&self, path: &Path, bytes: &[u8]) -> Result<AnalysisResult> {
        let warnings = Vec::new();
        let mut external = Vec::new();
        let deobfuscated_files = Vec::new();
        let deobfuscated_file_locations = Vec::new();

        let mut language = "Lua".to_string();
        let mut kind = "Source".to_string();
        let entry_point = None;

        // Detect Bytecode
        if bytes.len() >= 4 && bytes.starts_with(b"\x1bLua") {
            kind = "Bytecode".to_string();
            if bytes.len() >= 5 {
                let ver_byte = bytes[4];
                let major = ver_byte >> 4;
                let minor = ver_byte & 0x0f;
                language = format!("Lua {}.{}", major, minor);
            }
        } else if bytes.len() >= 3 && bytes.starts_with(b"\x1bLJ") {
            kind = "Bytecode (LuaJIT)".to_string();
            language = "LuaJIT".to_string();
            // LuaJIT version is tricky, usually in the next byte
            if bytes.len() >= 4 {
                let ver = bytes[3];
                // 1 = LuaJIT 1.x, 2 = LuaJIT 2.x
                language = format!("LuaJIT {}", ver);
            }
        }

        let strings = extract_ascii_strings(bytes, 4, 3000);
        let secrets = collect_secrets(&strings, &deobfuscated_files, &[], &[], &external);

        // Basic Preview if it's text
        if kind == "Source" {
            let preview = std::str::from_utf8(bytes)
                .unwrap_or("")
                .lines()
                .take(100)
                .collect::<Vec<_>>()
                .join("\n");

            external.push(ExternalToolOutput {
                tool: "preview".to_string(),
                exit_code: None,
                stdout: preview,
                stderr: String::new(),
            });
        } else {
            external.push(ExternalToolOutput {
                tool: "header_info".to_string(),
                exit_code: None,
                stdout: format!(
                    "Detected {} file.\nHeader bytes: {:02x?}",
                    language,
                    &bytes[0..std::cmp::min(bytes.len(), 16)]
                ),
                stderr: String::new(),
            });
        }

        // Layered Analysis Report
        let mut report = LayeredAnalysisReport::new(path.to_string_lossy().to_string());
        report.final_payload_type = if kind.contains("Bytecode") {
            "Lua Bytecode".to_string()
        } else {
            "Lua Source".to_string()
        };

        // 1. Entropy Check
        if let Some(layer) = layered_analysis::detect_high_entropy(bytes) {
            report.add_layer(layer);
        }

        // 2. Obfuscation Check
        if let Some(layer) = layered_analysis::detect_obfuscation(bytes, false) {
            report.add_layer(layer);
        }

        // 3. Specific Lua Obfuscation Patterns
        let s = String::from_utf8_lossy(bytes);
        if s.contains("loadstring") || s.contains("getfenv") {
            report.add_layer(layered_analysis::Layer {
                layer_type: layered_analysis::LayerType::Obfuscation,
                method: "Lua Dynamic Execution".to_string(),
                confidence: 60,
                details: "Usage of loadstring/getfenv detected.".to_string(),
                guide:
                    "Dynamic execution functions found. This is common in obfuscated Lua scripts."
                        .to_string(),
                extracted_files: Vec::new(),
            });
        }

        let mut result = AnalysisResult {
            file_path: path.to_path_buf(),
            file_size: bytes.len() as u64,
            file_format: "Lua Script".to_string(),
            language,
            kind,
            entry_point,
            python_entrypoint: None,
            imports: Vec::new(),
            sections: Vec::new(),
            strings,
            disassembly: Vec::new(),
            external,
            warnings,
            deobfuscated_files,
            deobfuscated_file_locations,
            js_files: Vec::new(),
            js_container: None,
            js_obfuscated: false,
            is_stealer: false,
            secrets,
            confidence_score: 0,
            extracted_dir: None,
            yara_matches: Vec::new(),
            layered_report: Some(report),
        };
        result.confidence_score = calculate_confidence_score(&result);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_misclassify_node_marker_as_pkg() {
        let bytes = b"NODE_PRESERVE_SYMLINKS_MAIN";
        assert_ne!(detect_js_container(bytes).as_deref(), Some("pkg"));
    }

    #[test]
    fn picks_non_rth_entrypoint() {
        let eps = vec![
            "pyiboot01_bootstrap.pyc".to_string(),
            "pyi_rth_inspect.pyc".to_string(),
            "pyi_rth_pkgutil.pyc".to_string(),
            "grabber_temp.pyc".to_string(),
        ];
        let chosen = extractor::pyinstaller_pick_entrypoint(&eps);
        assert_eq!(chosen.as_deref(), Some("grabber_temp.pyc"));
    }

    #[test]
    fn disassembles_python_311_marshaled_code_object() {
        let bytes: Vec<u8> = vec![
            227, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 243, 28, 0, 0, 0, 151,
            0, 2, 0, 101, 0, 100, 0, 166, 1, 0, 0, 171, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 100, 1,
            83, 0, 41, 2, 233, 123, 0, 0, 0, 78, 41, 1, 218, 5, 112, 114, 105, 110, 116, 169, 0,
            243, 0, 0, 0, 0, 250, 4, 120, 46, 112, 121, 250, 8, 60, 109, 111, 100, 117, 108, 101,
            62, 114, 7, 0, 0, 0, 1, 0, 0, 0, 115, 22, 0, 0, 0, 240, 3, 1, 1, 1, 216, 0, 5, 128, 5,
            128, 99, 129, 10, 132, 10, 128, 10, 128, 10, 128, 10, 114, 5, 0, 0, 0,
        ];
        let out = disassemble::disassemble_python_blob(&bytes, Some((3, 11))).unwrap();
        assert!(out.contains("RESUME"));
        assert!(out.contains("RETURN_VALUE"));
    }

    #[test]
    fn disassembles_marshaled_code_with_length_prefix() {
        let marshaled: Vec<u8> = vec![
            227, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 243, 28, 0, 0, 0, 151,
            0, 2, 0, 101, 0, 100, 0, 166, 1, 0, 0, 171, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 100, 1,
            83, 0, 41, 2, 233, 123, 0, 0, 0, 78, 41, 1, 218, 5, 112, 114, 105, 110, 116, 169, 0,
            243, 0, 0, 0, 0, 250, 4, 120, 46, 112, 121, 250, 8, 60, 109, 111, 100, 117, 108, 101,
            62, 114, 7, 0, 0, 0, 1, 0, 0, 0, 115, 22, 0, 0, 0, 240, 3, 1, 1, 1, 216, 0, 5, 128, 5,
            128, 99, 129, 10, 132, 10, 128, 10, 128, 10, 128, 10, 114, 5, 0, 0, 0,
        ];
        let mut blob = Vec::new();
        blob.extend_from_slice(&(marshaled.len() as u32).to_le_bytes());
        blob.extend_from_slice(&marshaled);
        let out = disassemble::disassemble_python_blob(&blob, Some((3, 11))).unwrap();
        assert!(out.contains("RESUME"));
    }

    #[test]
    fn disassembles_pyc_like_header_plus_marshaled_code() {
        let marshaled: Vec<u8> = vec![
            227, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 243, 28, 0, 0, 0, 151,
            0, 2, 0, 101, 0, 100, 0, 166, 1, 0, 0, 171, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 100, 1,
            83, 0, 41, 2, 233, 123, 0, 0, 0, 78, 41, 1, 218, 5, 112, 114, 105, 110, 116, 169, 0,
            243, 0, 0, 0, 0, 250, 4, 120, 46, 112, 121, 250, 8, 60, 109, 111, 100, 117, 108, 101,
            62, 114, 7, 0, 0, 0, 1, 0, 0, 0, 115, 22, 0, 0, 0, 240, 3, 1, 1, 1, 216, 0, 5, 128, 5,
            128, 99, 129, 10, 132, 10, 128, 10, 128, 10, 128, 10, 114, 5, 0, 0, 0,
        ];
        let mut blob = vec![0u8; 16];
        blob[2] = 0x0d;
        blob[3] = 0x0a;
        blob.extend_from_slice(&marshaled);
        let out = disassemble::disassemble_python_blob(&blob, Some((3, 11))).unwrap();
        assert!(out.contains("RETURN_VALUE"));
    }

    #[test]
    fn disassembles_module_from_minimal_pyz_archive() {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;

        let marshaled: Vec<u8> = vec![
            227, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 243, 28, 0, 0, 0, 151,
            0, 2, 0, 101, 0, 100, 0, 166, 1, 0, 0, 171, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 100, 1,
            83, 0, 41, 2, 233, 123, 0, 0, 0, 78, 41, 1, 218, 5, 112, 114, 105, 110, 116, 169, 0,
            243, 0, 0, 0, 0, 250, 4, 120, 46, 112, 121, 250, 8, 60, 109, 111, 100, 117, 108, 101,
            62, 114, 7, 0, 0, 0, 1, 0, 0, 0, 115, 22, 0, 0, 0, 240, 3, 1, 1, 1, 216, 0, 5, 128, 5,
            128, 99, 129, 10, 132, 10, 128, 10, 128, 10, 128, 10, 114, 5, 0, 0, 0,
        ];

        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&marshaled).unwrap();
        let compressed = enc.finish().unwrap();

        let module_pos = 12usize;
        let toc_pos = module_pos + compressed.len();

        let mut toc = Vec::new();
        toc.push(b'{');
        toc.push(b'u');
        toc.extend_from_slice(&8i32.to_le_bytes());
        toc.extend_from_slice(b"__main__");
        toc.push(b'(');
        toc.extend_from_slice(&3i32.to_le_bytes());
        toc.push(b'i');
        toc.extend_from_slice(&0i32.to_le_bytes());
        toc.push(b'i');
        toc.extend_from_slice(&(module_pos as i32).to_le_bytes());
        toc.push(b'i');
        toc.extend_from_slice(&(compressed.len() as i32).to_le_bytes());
        toc.push(b'0');

        let mut pyz = Vec::new();
        pyz.extend_from_slice(b"PYZ\0");
        pyz.extend_from_slice(&[0, 0, 0, 0]);
        pyz.extend_from_slice(&(toc_pos as i32).to_be_bytes());
        pyz.extend_from_slice(&compressed);
        pyz.extend_from_slice(&toc);

        let archive = extractor::PyInstallerArchive {
            py_major: 3,
            py_minor: 11,
            entries: vec![extractor::PyInstallerTocEntry {
                position: 0,
                compressed_size: pyz.len(),
                uncompressed_size: pyz.len(),
                compressed_flag: 0,
                type_code: b'z',
                name: "PYZ-00.pyz".to_string(),
            }],
        };

        let res = extractor::pyinstaller_try_disassemble_from_pyz(
            &archive,
            &pyz,
            Some((3, 11)),
            Some("__main__"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(res.0, "__main__");
        assert!(res.1.contains("RESUME"));
    }

    #[test]
    fn marshal_limits_prevent_huge_allocations() {
        let mut bytes = Vec::new();
        bytes.push(b'(');
        bytes.extend_from_slice(&(300_000i32).to_le_bytes());
        let mut r = disassemble::MarshalReader::new(&bytes, Some((3, 11)));
        let err = r.read_object().unwrap_err().to_string();
        assert!(err.contains("tuple too large"));
    }

    #[test]
    fn extracts_urls_from_analysis() {
        let result = AnalysisResult {
            file_path: PathBuf::from("x"),
            file_size: 0,
            file_format: "PE".to_string(),
            language: "Native".to_string(),
            kind: "binary".to_string(),
            entry_point: None,
            python_entrypoint: None,
            imports: Vec::new(),
            sections: Vec::new(),
            strings: vec![
                "noise".to_string(),
                "https://example.com/path?x=1".to_string(),
            ],
            disassembly: vec![InstructionLine {
                address: 0,
                bytes_hex: "".to_string(),
                mnemonic: "mov".to_string(),
                op_str: "rax, http://test.local/a)".to_string(),
            }],
            external: vec![ExternalToolOutput {
                tool: "python-dis".to_string(),
                exit_code: None,
                stdout: "LOAD_CONST 'https://a.b/c'".to_string(),
                stderr: String::new(),
            }],
            warnings: Vec::new(),
            deobfuscated_files: Vec::new(),
            deobfuscated_file_locations: Vec::new(),
            js_container: None,
            js_obfuscated: false,
            js_files: Vec::new(),
            is_stealer: false,
            secrets: Vec::new(),
            confidence_score: 1,
            extracted_dir: None,
            layered_report: None,
            yara_matches: Vec::new(),
        };

        let urls = extract_urls(&result);
        assert!(urls.contains(&"http://test.local/a".to_string()));
        assert!(urls.contains(&"https://example.com/path?x=1".to_string()));
        assert!(urls.contains(&"https://a.b/c".to_string()));
    }

    #[cfg(windows)]
    #[test]
    fn parses_pkg_vfs_from_fake_client() {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fake-malware")
            .join("fake-client.exe");
        if !p.exists() {
            return;
        }
        let bytes = std::fs::read(&p).unwrap();

        let marker = b"PAYLOAD_POSITION";
        let mut current_pos = 0usize;

        let parse_quoted_usize = |text: &str, name: &str| -> Option<usize> {
            let idx = text.find(name)?;
            let after = &text[idx..];
            let eq_pos = after.find('=')?;
            let after_eq = &after[eq_pos..];
            let q1 = after_eq.find('\'')?;
            let after_q1 = &after_eq[q1 + 1..];
            let q2 = after_q1.find('\'')?;
            after_q1[..q2].trim().parse::<usize>().ok()
        };

        let (payload_pos, payload_size, prelude_pos, prelude_size) = loop {
            let Some(rel) = bytes[current_pos..]
                .windows(marker.len())
                .position(|w| w == marker)
            else {
                panic!("PAYLOAD_POSITION marker not found");
            };

            let absolute_pos = current_pos + rel;
            current_pos = absolute_pos + marker.len();
            let lookahead = &bytes[absolute_pos..std::cmp::min(absolute_pos + 1200, bytes.len())];
            let s = String::from_utf8_lossy(lookahead);

            let Some(payload_pos) = parse_quoted_usize(&s, "PAYLOAD_POSITION") else {
                continue;
            };
            let Some(payload_size) = parse_quoted_usize(&s, "PAYLOAD_SIZE") else {
                continue;
            };
            let Some(prelude_pos) = parse_quoted_usize(&s, "PRELUDE_POSITION") else {
                continue;
            };
            let Some(prelude_size) = parse_quoted_usize(&s, "PRELUDE_SIZE") else {
                continue;
            };

            break (payload_pos, payload_size, prelude_pos, prelude_size);
        };

        let payload = &bytes[payload_pos..payload_pos + payload_size];
        let mut payload_decompressed = Vec::new();
        let payload_for_vfs: &[u8] = if payload.starts_with(&[0x1f, 0x8b]) {
            let mut d = flate2::read::GzDecoder::new(payload);
            d.read_to_end(&mut payload_decompressed).unwrap();
            payload_decompressed.as_slice()
        } else {
            payload
        };
        let prelude = &bytes[prelude_pos..prelude_pos + prelude_size];
        let prelude_text = String::from_utf8_lossy(prelude).into_owned();
        let (vfs, _entry, dict) = pkg_parse_prelude_tail(&prelude_text).unwrap();
        let extracted = pkg_extract_text_js_from_payload(payload_for_vfs, &vfs, &dict);

        assert!(vfs.as_object().is_some());
        assert!(dict.as_object().is_some());
        assert!(extracted.is_empty());
    }

    #[test]
    fn detects_lua_source() {
        let analyzer = LuaAnalyzer;
        let path = PathBuf::from("test.lua");
        let bytes = b"print('hello')";
        assert!(analyzer.can_handle(&path, bytes));
        let res = analyzer.analyze(&path, bytes).unwrap();
        assert_eq!(res.language, "Lua");
        assert_eq!(res.kind, "Source");
    }

    #[test]
    fn detects_lua_bytecode_51() {
        let analyzer = LuaAnalyzer;
        let path = PathBuf::from("test.out");
        let bytes = b"\x1bLua\x51\x00";
        assert!(analyzer.can_handle(&path, bytes));
        let res = analyzer.analyze(&path, bytes).unwrap();
        assert_eq!(res.language, "Lua 5.1");
        assert_eq!(res.kind, "Bytecode");
    }

    #[test]
    fn detects_embedded_lua_strings() {
        let strings = vec![
            "Some random string".to_string(),
            "lua_State".to_string(),
            "Another string".to_string(),
        ];
        assert_eq!(
            super::detect_embedded_lua(&strings),
            Some("Lua (Embedded API)".to_string())
        );

        let strings_jit = vec!["LuaJIT 2.1.0".to_string()];
        assert_eq!(
            super::detect_embedded_lua(&strings_jit),
            Some("LuaJIT".to_string())
        );
    }

    #[test]
    fn detects_luajit_bytecode() {
        let analyzer = LuaAnalyzer;
        let path = PathBuf::from("test.out");
        let bytes = b"\x1bLJ\x01";
        assert!(analyzer.can_handle(&path, bytes));
        let res = analyzer.analyze(&path, bytes).unwrap();
        assert_eq!(res.language, "LuaJIT 1");
        assert_eq!(res.kind, "Bytecode (LuaJIT)");
    }
}
