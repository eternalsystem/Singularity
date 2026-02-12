use aes::Aes256;
use aes_gcm::{
    Aes128Gcm,
    Aes256Gcm,
    AesGcm, // 32-byte key, 12-byte nonce
    Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose};
use cbc::Decryptor;
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};

use flate2::read::{GzDecoder, ZlibDecoder};
use lazy_static::lazy_static;
use regex::Regex;
use std::io::Read;
use std::path::Path;
use walkdir::WalkDir;

use crate::disassemble::{CodeObject, MarshalValue};

lazy_static! {
    // 32 bytes = 256 bits -> 43 chars + '='
    // Support both Standard (+/) and URL-Safe (-_)
    static ref RE_BASE64_KEY_32: Regex = Regex::new(r"[A-Za-z0-9+/_\-]{43}=?").unwrap();
    // 16 bytes = 128 bits -> 22 chars + '=='
    static ref RE_BASE64_KEY_16: Regex = Regex::new(r"[A-Za-z0-9+/_\-]{22}(?:==)?").unwrap();

    // Hex keys (32 bytes = 64 hex chars, 16 bytes = 32 hex chars)
    static ref RE_HEX_KEY_32: Regex = Regex::new(r"(?i)\b[a-f0-9]{64}\b").unwrap();
    static ref RE_HEX_KEY_16: Regex = Regex::new(r"(?i)\b[a-f0-9]{32}\b").unwrap();

    // Variable assignment (common in scripts)
    static ref RE_KEY_ASSIGN: Regex = Regex::new(r"(?i)(?:key|iv|secret|password|token)\s*=\s*(?:b|u)?['\x22]([A-Za-z0-9+/=_\-]+)['\x22]").unwrap();

    // Specific for Python disassembly (LOAD_CONST)
    // Matches LOAD_CONST index ('string') or ("string") or (b'string')
    // Capture group 1 is the content (simplified to avoid backreferences)
    static ref RE_LOAD_CONST_KEY: Regex = Regex::new(r"LOAD_CONST\s+\d+\s+\(?(?:b|u)?['\x22]([A-Za-z0-9+/=_\-]+)['\x22]\)?").unwrap();
}

/// Structure holding potential keys, IVs, and payloads found during scanning.
#[derive(Debug, Default)]
pub struct ScanResult {
    pub potential_keys: Vec<Vec<u8>>,
    pub potential_ivs: Vec<Vec<u8>>,
    pub potential_payloads: Vec<Vec<u8>>,
    pub potential_files: Vec<String>,
}

pub fn scan_code_object(code: &CodeObject) -> ScanResult {
    let mut result = ScanResult::default();
    scan_code_recursive(code, &mut result);
    // Dedup
    result.potential_keys.sort();
    result.potential_keys.dedup();
    result.potential_ivs.sort();
    result.potential_ivs.dedup();
    result.potential_files.sort();
    result.potential_files.dedup();
    result
}

pub fn scan_text(text: &str) -> ScanResult {
    let mut result = ScanResult::default();
    for line in text.lines() {
        analyze_string(line, &mut result);
    }
    result.potential_keys.sort();
    result.potential_keys.dedup();
    result.potential_ivs.sort();
    result.potential_ivs.dedup();
    result.potential_files.sort();
    result.potential_files.dedup();
    result
}

pub fn merge_scan_results(target: &mut ScanResult, other: ScanResult) {
    target.potential_keys.extend(other.potential_keys);
    target.potential_ivs.extend(other.potential_ivs);
    target.potential_payloads.extend(other.potential_payloads);
    target.potential_files.extend(other.potential_files);
    target.potential_keys.sort();
    target.potential_keys.dedup();
    target.potential_ivs.sort();
    target.potential_ivs.dedup();
    target.potential_files.sort();
    target.potential_files.dedup();
}

fn scan_code_recursive(code: &CodeObject, result: &mut ScanResult) {
    // Scan constants
    log!(
        "[Heuristic] Scanning code object with {} constants",
        code.consts.len()
    );
    for const_val in &code.consts {
        scan_value_recursive(const_val, result);
    }
}

fn scan_value_recursive(val: &MarshalValue, result: &mut ScanResult) {
    match val {
        MarshalValue::Code(sub_code) => scan_code_recursive(sub_code, result),
        MarshalValue::String(s) => analyze_string(s, result),
        MarshalValue::Bytes(b) => {
            // Check for raw keys/IVs
            process_decoded_bytes(b.clone(), result);

            // If bytes look like a string, try to analyze as string too
            if let Ok(s) = std::str::from_utf8(b) {
                analyze_string(s, result);
            }
            // Also treat as payload if large enough
            if b.len() > 1024 {
                // Arbitrary threshold for payload
                result.potential_payloads.push(b.clone());
            }
        }
        MarshalValue::Tuple(items) | MarshalValue::List(items) => {
            // Check for integer lists acting as byte arrays (common obfuscation)
            let mut byte_array = Vec::new();
            let mut is_byte_array = true;
            // Limit check size to avoid massive allocations for huge lists that aren't keys
            if items.len() <= 128 {
                for item in items {
                    match item {
                        MarshalValue::Int(val) => {
                            if *val >= 0 && *val <= 255 {
                                byte_array.push(*val as u8);
                            } else {
                                is_byte_array = false;
                                break;
                            }
                        }
                        MarshalValue::Int64(val) => {
                            if *val >= 0 && *val <= 255 {
                                byte_array.push(*val as u8);
                            } else {
                                is_byte_array = false;
                                break;
                            }
                        }
                        _ => {
                            is_byte_array = false;
                            break;
                        }
                    }
                }
                if is_byte_array && !byte_array.is_empty() {
                    process_decoded_bytes(byte_array, result);
                }
            }

            for item in items {
                scan_value_recursive(item, result);
            }
        }
        MarshalValue::Set(items) | MarshalValue::FrozenSet(items) => {
            for item in items {
                scan_value_recursive(item, result);
            }
        }
        MarshalValue::Dict(items) => {
            for (k, v) in items {
                scan_value_recursive(k, result);
                scan_value_recursive(v, result);
            }
        }
        _ => {}
    }
}

fn analyze_string(s: &str, result: &mut ScanResult) {
    let s_trimmed = s.trim();

    // Check for filenames like "stealer.aes" or typical enc files
    if s_trimmed.ends_with(".aes") || s_trimmed.ends_with(".bin") || s_trimmed.ends_with(".enc") {
        log!(
            "[Heuristic] Found potential encrypted file reference: {}",
            s_trimmed
        );
        result.potential_files.push(s_trimmed.to_string());
    }

    let candidates = decode_base64_candidates(s_trimmed);
    for decoded in candidates {
        process_decoded_bytes(decoded, result);
    }

    // 2. Try Regex scanning for embedded keys

    // Prioritize LOAD_CONST for disassembly files
    for cap in RE_LOAD_CONST_KEY.captures_iter(s) {
        if let Some(match_str) = cap.get(1) {
            let s_val = match_str.as_str();
            // Try to decode
            if let Ok(decoded) = general_purpose::STANDARD.decode(s_val) {
                if decoded.len() > 128 {
                    // Likely a payload
                    log!(
                        "[Heuristic] Found potential payload in LOAD_CONST (len={})",
                        decoded.len()
                    );
                    result.potential_payloads.push(decoded);
                } else {
                    process_decoded_bytes(decoded, result);
                }
            }
        }
    }

    // Check for variable assignments
    for cap in RE_KEY_ASSIGN.captures_iter(s) {
        if let Some(match_str) = cap.get(1) {
            for decoded in decode_base64_candidates(match_str.as_str()) {
                process_decoded_bytes(decoded, result);
            }
        }
    }

    // Check for Hex keys
    for cap in RE_HEX_KEY_32.captures_iter(s) {
        if let Ok(decoded) = hex::decode(&cap[0]) {
            process_decoded_bytes(decoded, result);
        }
    }
    for cap in RE_HEX_KEY_16.captures_iter(s) {
        if let Ok(decoded) = hex::decode(&cap[0]) {
            process_decoded_bytes(decoded, result);
        }
    }

    for cap in RE_BASE64_KEY_32.captures_iter(s) {
        for decoded in decode_base64_candidates(&cap[0]) {
            if decoded.len() == 32 {
                result.potential_keys.push(decoded);
            }
        }
    }

    for cap in RE_BASE64_KEY_16.captures_iter(s) {
        for decoded in decode_base64_candidates(&cap[0]) {
            if decoded.len() == 16 {
                result.potential_keys.push(decoded.clone());
                result.potential_ivs.push(decoded);
            }
        }
    }
}

fn decode_base64_candidates(s: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if let Ok(decoded) = general_purpose::STANDARD.decode(s) {
        out.push(decoded);
    }
    let cleaned = s.trim_matches(|c| c == '"' || c == '\'');
    if cleaned != s {
        if let Ok(decoded) = general_purpose::STANDARD.decode(cleaned) {
            out.push(decoded);
        }
    }
    if !cleaned.contains('=') {
        if let Ok(decoded) = general_purpose::STANDARD_NO_PAD.decode(cleaned) {
            out.push(decoded);
        }
        let mut padded = cleaned.to_string();
        let rem = padded.len() % 4;
        if rem != 0 {
            padded.push_str(&"=".repeat(4 - rem));
        }
        if let Ok(decoded) = general_purpose::STANDARD.decode(&padded) {
            out.push(decoded);
        }
    }
    out
}

fn process_decoded_bytes(decoded: Vec<u8>, result: &mut ScanResult) {
    match decoded.len() {
        32 => {
            log!(
                "[Heuristic] Accepted 32-byte key: {}",
                general_purpose::STANDARD.encode(&decoded)
            );
            result.potential_keys.push(decoded);
        }
        24 => result.potential_keys.push(decoded), // AES-192?
        16 => {
            log!(
                "[Heuristic] Accepted 16-byte key/IV: {}",
                general_purpose::STANDARD.encode(&decoded)
            );
            // Could be Key (AES-128) or IV
            result.potential_keys.push(decoded.clone());
            result.potential_ivs.push(decoded);
        }
        12 => result.potential_ivs.push(decoded), // GCM Nonce standard
        _ => {}
    }
}

pub fn attempt_decryption(result: &ScanResult, base_path: &Path) -> Option<(String, Vec<u8>)> {
    let search_dir = if base_path.is_file() {
        base_path.parent().unwrap_or(base_path)
    } else {
        base_path
    };
    println!(
        "[Heuristic] Scanning directory {} for potential encrypted payloads...",
        search_dir.display()
    );
    let mut files_to_try = result.potential_files.clone();

    // Add directory scan fallback: look for .aes/.bin/.enc files in search_dir (recursively)
    // We limit depth to 3 levels to avoid scanning entire drives if run on root
    for entry in WalkDir::new(search_dir)
        .max_depth(3)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() {
            if let Some(name) = entry.file_name().to_str() {
                if name.ends_with(".aes") || name.ends_with(".bin") || name.ends_with(".enc") {
                    // Get path relative to search_dir if possible, or just filename
                    let rel_path = entry
                        .path()
                        .strip_prefix(search_dir)
                        .unwrap_or_else(|_| entry.path())
                        .to_string_lossy()
                        .to_string();

                    if !files_to_try.contains(&rel_path) {
                        // // log!("[Heuristic] Found potential file via fallback: {}", rel_path);
                        files_to_try.push(rel_path);
                    }
                }
            }
        }
    }

    // log!("[Heuristic] Files to try: {:?}", files_to_try);
    // log!("[Heuristic] Keys: {}, IVs: {}", result.potential_keys.len(), result.potential_ivs.len());

    // Print found keys for debugging (User request)
    if !result.potential_keys.is_empty() {
        // println!("[Heuristic] Found {} potential keys:", result.potential_keys.len());
        // for (i, key) in result.potential_keys.iter().enumerate() {
        //     if i >= 10 {
        //         // println!("[Heuristic] ... and {} more", result.potential_keys.len() - 10);
        //         break;
        //     }
        //     // println!("[Heuristic] Key {}: {}", i, general_purpose::STANDARD.encode(key));
        // }
    } else {
        // println!("[Heuristic] No keys found.");
    }

    // 1. Try file-based decryption (Stealer style)
    for filename in &files_to_try {
        let file_path = search_dir.join(filename);
        if file_path.exists() {
            if let Ok(data) = std::fs::read(&file_path) {
                // log!("[Heuristic] Read {} bytes from {}", data.len(), filename);
                // Strategy: Stealer (Reverse -> Zlib -> AES-GCM)
                let mut reversed_data = data.clone();
                reversed_data.reverse();
                if let Ok(decompressed) = zlib_decompress(&reversed_data) {
                    log!(
                        "[Heuristic] Python Malware Artifact Detected (Stealer): Strategy 1 (Rev+Zlib) success for {}, len: {}",
                        filename,
                        decompressed.len()
                    );
                    if let Some(decrypted) = try_decrypt_combinations(&decompressed, result) {
                        return Some((
                            format!("Decrypted from {} (Stealer logic)", filename),
                            decrypted,
                        ));
                    }
                } else {
                    // log!("[Heuristic] Strategy 1 (Rev+Zlib) failed for {}", filename);
                }

                // Try Zlib decompress on original
                if let Ok(decompressed) = zlib_decompress(&data) {
                    log!(
                        "[Heuristic] Strategy 2 (Zlib) success for {}, len: {}",
                        filename,
                        decompressed.len()
                    );
                    if let Some(decrypted) = try_decrypt_combinations(&decompressed, result) {
                        return Some((
                            format!("Decrypted from {} (Zlib -> AES)", filename),
                            decrypted,
                        ));
                    }
                }

                // Try Direct AES-GCM/CBC
                if let Some(decrypted) = try_decrypt_combinations(&data, result) {
                    log!(
                        "[Heuristic] Strategy 3 (Direct AES) success for {}",
                        filename
                    );
                    return Some((
                        format!("Decrypted from {} (Direct AES)", filename),
                        decrypted,
                    ));
                }
            }
        } else {
            // log!("[Heuristic] File not found: {}", file_path.display());
        }
    }

    // 2. Try embedded payload decryption
    for payload in &result.potential_payloads {
        // Same strategies
        let mut reversed = payload.clone();
        reversed.reverse();

        // Helper to check for webhooks/URLs
        let check_webhook = |data: &[u8], desc: &str| -> Option<(String, Vec<u8>)> {
            if let Ok(s) = std::str::from_utf8(data) {
                if s.contains("http://") || s.contains("https://") || s.contains("discord.com") {
                    return Some((format!("{} [Contains URL/Webhook]", desc), data.to_vec()));
                }
            }
            None
        };

        // Strategy: Reverse -> Zlib -> AES
        if let Ok(decompressed) = zlib_decompress(&reversed) {
            if let Some(decrypted) = try_decrypt_combinations(&decompressed, result) {
                if let Some(res) = check_webhook(
                    &decrypted,
                    "Decrypted from embedded payload (Stealer logic)",
                ) {
                    return Some(res);
                }
                // If no webhook, keep as candidate? For now just return if we don't find a better one later?
                // But we want to prioritize webhooks.
                // Let's store it and continue searching if it doesn't have a webhook.
            }
        }

        // Strategy: Zlib -> AES
        if let Ok(decompressed) = zlib_decompress(payload) {
            if let Some(decrypted) = try_decrypt_combinations(&decompressed, result) {
                if let Some(res) =
                    check_webhook(&decrypted, "Decrypted from embedded payload (Zlib -> AES)")
                {
                    return Some(res);
                }
            }
        }

        // Strategy: Gzip -> AES (New Generic Method)
        if let Ok(decompressed) = gzip_decompress(payload) {
            if let Some(decrypted) = try_decrypt_combinations(&decompressed, result) {
                if let Some(res) =
                    check_webhook(&decrypted, "Decrypted from embedded payload (Gzip -> AES)")
                {
                    return Some(res);
                }
            }
        }

        // Strategy: AES -> Gzip (Common in Python loaders)
        if let Some(decrypted) = try_decrypt_combinations(payload, result) {
            // Try Gzip on decrypted
            if let Ok(decompressed) = gzip_decompress(&decrypted) {
                if let Some(res) = check_webhook(
                    &decompressed,
                    "Decrypted from embedded payload (AES -> Gzip)",
                ) {
                    return Some(res);
                }
                return Some((
                    "Decrypted from embedded payload (AES -> Gzip)".to_string(),
                    decompressed,
                ));
            }

            // Try Zlib on decrypted
            if let Ok(decompressed) = zlib_decompress(&decrypted) {
                if let Some(res) = check_webhook(
                    &decompressed,
                    "Decrypted from embedded payload (AES -> Zlib)",
                ) {
                    return Some(res);
                }
                return Some((
                    "Decrypted from embedded payload (AES -> Zlib)".to_string(),
                    decompressed,
                ));
            }

            if let Some(res) =
                check_webhook(&decrypted, "Decrypted from embedded payload (Direct AES)")
            {
                return Some(res);
            }
            // Fallback return if nothing else matches
            return Some((
                "Decrypted from embedded payload (Direct AES)".to_string(),
                decrypted,
            ));
        }
    }

    None
}

fn zlib_decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

fn gzip_decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

pub fn try_decrypt_combinations(data: &[u8], result: &ScanResult) -> Option<Vec<u8>> {
    // We need at least Tag size (16) or block size
    if data.len() < 16 {
        return None;
    }

    for key in &result.potential_keys {
        for iv in &result.potential_ivs {
            // Try AES-256-GCM
            if key.len() == 32 {
                if iv.len() == 12 {
                    if let Ok(decrypted) = try_aes256_gcm(key, iv, data) {
                        println!(
                            "[Heuristic] Success with AES-256-GCM! Key: {}, IV: {}",
                            general_purpose::STANDARD.encode(key),
                            general_purpose::STANDARD.encode(iv)
                        );
                        return Some(decrypted);
                    }
                } else if iv.len() == 16 {
                    if let Ok(decrypted) = try_aes256_gcm_16(key, iv, data) {
                        println!(
                            "[Heuristic] Success with AES-256-GCM-16! Key: {}, IV: {}",
                            general_purpose::STANDARD.encode(key),
                            general_purpose::STANDARD.encode(iv)
                        );
                        return Some(decrypted);
                    }
                }

                // Try AES-256-CBC (IV must be 16 bytes)
                if iv.len() == 16 {
                    if let Ok(decrypted) = try_aes256_cbc(key, iv, data) {
                        // Check if result is meaningful before logging success
                        // AES-CBC with PKCS7 padding can often "succeed" on random data (approx 1/256 chance)
                        if is_meaningful_content(&decrypted) {
                            println!(
                                "[Heuristic] Success with AES-256-CBC! Key: {}, IV: {}",
                                general_purpose::STANDARD.encode(key),
                                general_purpose::STANDARD.encode(iv)
                            );
                            return Some(decrypted);
                        }
                    }
                }
            }
            // Try AES-128-GCM
            if key.len() == 16 {
                if iv.len() == 12 {
                    if let Ok(decrypted) = try_aes128_gcm(key, iv, data) {
                        println!(
                            "[Heuristic] Success with AES-128-GCM! Key: {}, IV: {}",
                            general_purpose::STANDARD.encode(key),
                            general_purpose::STANDARD.encode(iv)
                        );
                        return Some(decrypted);
                    }
                } else if iv.len() == 16 {
                    if let Ok(decrypted) = try_aes128_gcm_16(key, iv, data) {
                        println!(
                            "[Heuristic] Success with AES-128-GCM-16! Key: {}, IV: {}",
                            general_purpose::STANDARD.encode(key),
                            general_purpose::STANDARD.encode(iv)
                        );
                        return Some(decrypted);
                    }
                }

                // Try AES-128-CBC
                if iv.len() == 16 {
                    if let Ok(decrypted) = try_aes128_cbc(key, iv, data) {
                        if is_meaningful_content(&decrypted) {
                            println!(
                                "[Heuristic] Success with AES-128-CBC! Key: {}, IV: {}",
                                general_purpose::STANDARD.encode(key),
                                general_purpose::STANDARD.encode(iv)
                            );
                            return Some(decrypted);
                        }
                    }
                }
            }
        }
    }
    None
}

pub fn is_meaningful_content(data: &[u8]) -> bool {
    // 1. Must be valid UTF-8
    if let Ok(s) = std::str::from_utf8(data) {
        // 2. Must contain at least some printable characters and not just control codes
        // Allow tabs, newlines
        let printables = s
            .chars()
            .filter(|c| !c.is_control() || c.is_whitespace())
            .count();
        if printables > 0 && printables as f32 / s.chars().count() as f32 > 0.8 {
            return true;
        }
    }
    // Or if it looks like a known binary format (Zlib header, etc.)
    if data.len() > 2
        && data[0] == 0x78
        && (data[1] == 0x9C || data[1] == 0x01 || data[1] == 0xDA || data[1] == 0x5E)
    {
        return true;
    }

    false
}

fn try_aes256_cbc(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    type Aes256Cbc = Decryptor<Aes256>;
    let decryptor = Aes256Cbc::new_from_slices(key, iv)
        .map_err(|e| anyhow::anyhow!("Invalid Key/IV length: {}", e))?;

    // We work on a clone because decrypt_padded_mut modifies in place
    let mut buf = data.to_vec();

    // Try PKCS7 padding
    let decrypted = decryptor
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| anyhow::anyhow!("Decryption failed (padding error?): {:?}", e))?;

    Ok(decrypted.to_vec())
}

fn try_aes128_cbc(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    type Aes128Cbc = Decryptor<aes::Aes128>;
    let decryptor = Aes128Cbc::new_from_slices(key, iv)
        .map_err(|e| anyhow::anyhow!("Invalid Key/IV length: {}", e))?;

    let mut buf = data.to_vec();
    let decrypted = decryptor
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| anyhow::anyhow!("Decryption failed (padding error?): {:?}", e))?;

    Ok(decrypted.to_vec())
}

fn try_aes256_gcm(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(key);
    // Nonce size can vary, but typically 12 bytes (96 bits)
    if iv.len() != 12 {
        anyhow::bail!("Invalid IV length for GCM");
    }
    let nonce = Nonce::from_slice(iv);
    let cipher = Aes256Gcm::new(key);

    cipher
        .decrypt(nonce, data)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))
}

fn try_aes128_gcm(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let key = aes_gcm::Key::<Aes128Gcm>::from_slice(key);
    if iv.len() != 12 {
        anyhow::bail!("Invalid IV length for GCM");
    }
    let nonce = Nonce::from_slice(iv);
    let cipher = Aes128Gcm::new(key);

    cipher
        .decrypt(nonce, data)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))
}

// Helper for 16-byte IVs
fn try_aes256_gcm_16(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    type Aes256Gcm16 = AesGcm<aes::Aes256, aes_gcm::aead::generic_array::typenum::U16>;
    let key = aes_gcm::Key::<Aes256Gcm16>::from_slice(key);
    if iv.len() != 16 {
        anyhow::bail!("Invalid IV length for GCM 16");
    }
    let nonce = aes_gcm::aead::generic_array::GenericArray::from_slice(iv);
    let cipher = Aes256Gcm16::new(key);

    cipher
        .decrypt(nonce, data)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))
}

fn try_aes128_gcm_16(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    type Aes128Gcm16 = AesGcm<aes::Aes128, aes_gcm::aead::generic_array::typenum::U16>;
    let key = aes_gcm::Key::<Aes128Gcm16>::from_slice(key);
    if iv.len() != 16 {
        anyhow::bail!("Invalid IV length for GCM 16");
    }
    let nonce = aes_gcm::aead::generic_array::GenericArray::from_slice(iv);
    let cipher = Aes128Gcm16::new(key);

    cipher
        .decrypt(nonce, data)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disassemble::{CodeObject, MarshalValue};

    #[test]
    fn test_scan_specific_key() {
        let key_str = "QDZxWzOp/K44pDFCLOB3sy2SW0zBw1HtN+7z3wvSkzs=";
        let mut result = ScanResult::default();

        // Test direct string analysis
        analyze_string(key_str, &mut result);
        result.potential_keys.sort();
        result.potential_keys.dedup();
        assert_eq!(
            result.potential_keys.len(),
            1,
            "Should find key in direct string"
        );
        assert_eq!(result.potential_keys[0].len(), 32);

        // Test with junk
        let junk_str = "Garbage... QDZxWzOp/K44pDFCLOB3sy2SW0zBw1HtN+7z3wvSkzs= More garbage";
        let mut result_junk = ScanResult::default();
        analyze_string(junk_str, &mut result_junk);
        result_junk.potential_keys.sort();
        result_junk.potential_keys.dedup();
        assert_eq!(
            result_junk.potential_keys.len(),
            1,
            "Should find key in junk string via Regex"
        );
        assert_eq!(result_junk.potential_keys[0], result.potential_keys[0]);
    }

    #[test]
    fn test_scan_dict() {
        let key_str = "QDZxWzOp/K44pDFCLOB3sy2SW0zBw1HtN+7z3wvSkzs=";
        let code = CodeObject {
            argcount: 0,
            posonlyargcount: 0,
            kwonlyargcount: 0,
            stacksize: 0,
            flags: 0,
            code: vec![],
            consts: vec![MarshalValue::Dict(vec![(
                MarshalValue::String("key".to_string()),
                MarshalValue::String(key_str.to_string()),
            )])],
            names: vec![],
            varnames: vec![],
            freevars: vec![],
            cellvars: vec![],
            localsplusnames: vec![],
            localspluskinds: vec![],
            filename: "test.py".to_string(),
            name: "test".to_string(),
            qualname: "test".to_string(),
            firstlineno: 1,
            linetable: vec![],
            exceptiontable: vec![],
        };

        let result = scan_code_object(&code);
        assert_eq!(result.potential_keys.len(), 1, "Should find key in Dict");
    }
}
