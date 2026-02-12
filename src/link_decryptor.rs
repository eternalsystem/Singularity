#![allow(dead_code)]
use crate::disassemble::{CodeObject, MarshalValue};
use crate::heuristic_decryptor;
// use crate::tools_manager::ToolManager;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use base64::{Engine as _, engine::general_purpose};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;
// use std::process::Command;
// #[cfg(windows)]
// use std::os::windows::process::CommandExt;
// use anyhow::Context;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

use regex::Regex;

const PYTHON_DECRYPTOR_SCRIPT: &str = r#"
import sys
import marshal
import base64
import struct
import os

# Try to import cryptography, handle failure gracefully
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    print("Error: cryptography module not found")
    HAS_CRYPTO = False

def get_strings_and_bytes(obj, str_list, bytes_list):
    if isinstance(obj, str):
        str_list.add(obj)
    elif isinstance(obj, bytes):
        bytes_list.add(obj)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            get_strings_and_bytes(item, str_list, bytes_list)
    elif hasattr(obj, 'co_consts'): # Code object
        for item in obj.co_consts:
            get_strings_and_bytes(item, str_list, bytes_list)

def try_decrypt(candidate, password):
    if not HAS_CRYPTO: return None
    try:
        if len(candidate) < 32: return None
        salt = candidate[:16]
        iv = candidate[16:32]
        ciphertext = candidate[32:]
        
        # Heuristic: Check if ciphertext length is multiple of block size (16)
        if len(ciphertext) % 16 != 0: return None

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()
        return plaintext.decode('utf-8')
    except Exception as e:
        return None

def main():
    if len(sys.argv) < 2:
        print("Usage: script.py <file_path>")
        return

    path = sys.argv[1]
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return
    
    # Try to load code object
    code_obj = None
    # Standard pyc headers are 16 bytes in 3.7+, but could be 8 or 12 in older/different versions
    # We also try 0 if it's a raw marshalled object
    for skip in [0, 16, 12, 8]:
        if len(data) <= skip: continue
        try:
            code_obj = marshal.loads(data[skip:])
            print(f"Successfully loaded code object (skip={skip})")
            break
        except Exception:
            pass
            
    candidates = set()
    passwords = set()
    
    if code_obj:
        get_strings_and_bytes(code_obj, passwords, candidates)
    else:
        print("Failed to marshal load, falling back to raw scan")
        # Fallback: simple regex-like scan on raw bytes
        # Find all null-terminated or length-prefixed strings? 
        # Actually, let's just look for printable strings
        import re
        try:
            text = data.decode('utf-8', errors='ignore')
            # Extract potential base64 strings
            b64_matches = re.findall(r'[A-Za-z0-9+/=]{32,}', text)
            for m in b64_matches:
                passwords.add(m)
                try:
                    b = base64.b64decode(m)
                    if len(b) >= 32: candidates.add(b)
                except: pass
            
            # Extract other strings
            str_matches = re.findall(r'[ -~]{4,}', text)
            for m in str_matches:
                passwords.add(m)
        except:
            pass
            
    # Also scan passwords for Base64 blobs (sometimes the blob is stored as a base64 string const)
    for s in list(passwords):
        if len(s) > 32:
            try:
                b = base64.b64decode(s)
                if len(b) > 32:
                    candidates.add(b)
            except:
                pass

    print(f"Scanning {len(candidates)} candidates with {len(passwords)} passwords...")
    
    found = []
    for pwd in passwords:
        if len(pwd) < 4: continue
        for cand in candidates:
             res = try_decrypt(cand, pwd)
             if res:
                 if "http" in res or "discord" in res:
                     print(f"FOUND_LINK: {res}")
                     found.append(res)
                 elif all(32 <= ord(c) <= 126 for c in res): # Printable
                     print(f"FOUND_DECRYPTED: {res}")
                     found.append(res)

if __name__ == "__main__":
    main()
"#;

pub fn run_python_decryptor(file_path: &std::path::Path) -> Vec<String> {
    let mut results = Vec::new();

    // Check if python is available
    let python_cmd = if cfg!(target_os = "windows") {
        "python"
    } else {
        "python3"
    };
    if std::process::Command::new(python_cmd)
        .arg("--version")
        .output()
        .is_err()
    {
        return results;
    }

    let script_path = std::env::temp_dir().join("singularity_decryptor.py");
    if std::fs::write(&script_path, PYTHON_DECRYPTOR_SCRIPT).is_err() {
        return results;
    }

    match std::process::Command::new(python_cmd)
        .arg(&script_path)
        .arg(file_path)
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            crate::log!("[LinkDecryptor] Python Output:\n{}", stdout);
            if !stderr.is_empty() {
                crate::log!("[LinkDecryptor] Python Stderr:\n{}", stderr);
            }

            for line in stdout.lines() {
                if let Some(link) = line.strip_prefix("FOUND_LINK: ") {
                    results.push(link.trim().to_string());
                } else if let Some(dec) = line.strip_prefix("FOUND_DECRYPTED: ") {
                    // Optional: include generic decrypted strings if they look interesting
                    if dec.contains("http") || dec.contains("webhook") {
                        results.push(dec.trim().to_string());
                    }
                }
            }
        }
        Err(e) => {
            crate::log!("[LinkDecryptor] Failed to execute python script: {}", e);
        }
    }

    results
}

/// Analyzes a CodeObject (from Python disassembly) to find and decrypt encrypted links (Webhooks, C2, etc.)
pub fn scan_and_decrypt_links(code: &CodeObject) -> Vec<String> {
    crate::log!("[LinkDecryptor] Starting LinkDecryptor analysis...");

    // 1. Use the heuristic decryptor to find potential keys/IVs
    let scan_result = heuristic_decryptor::scan_code_object(code);
    crate::log!(
        "[LinkDecryptor] Found {} potential keys and {} potential IVs",
        scan_result.potential_keys.len(),
        scan_result.potential_ivs.len()
    );

    // 2. Collect potential encrypted candidates AND potential password strings
    let mut candidates = Vec::new();
    let mut string_candidates = Vec::new();
    collect_candidates_recursive(code, &mut candidates, &mut string_candidates);
    crate::log!(
        "[LinkDecryptor] Found {} potential encrypted candidates and {} string candidates",
        candidates.len(),
        string_candidates.len()
    );

    decrypt_candidates(candidates, string_candidates, Some(&scan_result))
}

/// Analyzes disassembly text (fallback when CodeObject parsing fails)
pub fn scan_disassembly_text(text: &str) -> Vec<String> {
    crate::log!("[LinkDecryptor] Scanning disassembly text (fallback)...");
    let scan_result = heuristic_decryptor::scan_text(text);
    let mut candidates = Vec::new();
    let mut string_candidates = Vec::new();

    // 1. Regex to find ALL content inside single or double quotes
    // Matches: 'string' or "string"
    // Rust regex doesn't support backreferences (\1), so we use alternation
    let re_quotes = Regex::new(r#"(?s)'(.*?)'|"(.*?)"#).unwrap();

    for cap in re_quotes.captures_iter(text) {
        // Content is in group 1 (single quotes) or group 2 (double quotes)
        let match_content = cap.get(1).or(cap.get(2));

        if let Some(m) = match_content {
            // Content inside quotes
            let s = m.as_str().to_string();

            // Add raw string (important for passwords)
            // FILTER: Ignore short strings and common keywords to reduce false positives
            if s.len() > 6 && !is_common_keyword(&s) {
                if !string_candidates.contains(&s) {
                    string_candidates.push(s.clone());
                }
            }

            let clean_s = normalize_disassembly_string(&s);

            if !clean_s.is_empty() {
                if clean_s.len() > 6 && !is_common_keyword(&clean_s) {
                    if !string_candidates.contains(&clean_s) {
                        string_candidates.push(clean_s.clone());
                    }
                }
                // Stricter length for encrypted blobs (Base64 of 16 bytes is ~24 chars)
                if clean_s.len() >= 24 {
                    candidates.push(clean_s.as_bytes().to_vec());
                }
            }

            if let Some(decoded) = decode_escaped_bytes(&s) {
                // Stricter length for decoded bytes
                if decoded.len() >= 16 {
                    candidates.push(decoded.clone());
                }
                if let Ok(decoded_str) = String::from_utf8(decoded) {
                    if decoded_str.len() > 6
                        && !string_candidates.contains(&decoded_str)
                        && !is_common_keyword(&decoded_str)
                    {
                        string_candidates.push(decoded_str);
                    }
                }
            }
        }
    }

    // 2. Also try to find long contiguous strings (potential Base64 blobs)
    // Increased min length to 32 to avoid short noise
    let re_blob = Regex::new(r"[A-Za-z0-9+/=]{32,}").unwrap();
    for cap in re_blob.captures_iter(text) {
        if let Some(m) = cap.get(0) {
            let s = m.as_str().to_string();
            if !string_candidates.contains(&s) && !is_common_keyword(&s) {
                string_candidates.push(s.clone());
                candidates.push(s.as_bytes().to_vec());
            }
        }
    }

    crate::log!(
        "[LinkDecryptor] Text scan found {} candidates",
        string_candidates.len()
    );

    decrypt_candidates(candidates, string_candidates, Some(&scan_result))
}

fn is_common_keyword(s: &str) -> bool {
    let keywords = [
        "None",
        "True",
        "False",
        "self",
        "args",
        "kwargs",
        "return",
        "print",
        "append",
        "join",
        "split",
        "replace",
        "strip",
        "format",
        "decode",
        "encode",
        "utf-8",
        "ascii",
        "base64",
        "sys",
        "os",
        "socket",
        "threading",
        "time",
        "random",
        "math",
        "json",
        "requests",
        "urllib",
        "types",
        "object",
        "loads",
        "dumps",
        "urlopen",
        "read",
        "write",
        "open",
        "close",
        "get",
        "post",
        "put",
        "delete",
        "update",
        "items",
        "keys",
        "values",
        "start",
        "run",
        "exit",
        "main",
        "init",
        "str",
        "int",
        "float",
        "bool",
        "list",
        "dict",
        "set",
        "tuple",
        "bytes",
        "bytearray",
        "range",
        "len",
        "enumerate",
        "zip",
        "map",
        "filter",
        "lambda",
        "def",
        "class",
        "import",
        "from",
        "try",
        "except",
        "finally",
        "raise",
        "assert",
        "with",
        "as",
        "pass",
        "break",
        "continue",
        "if",
        "elif",
        "else",
        "for",
        "while",
        "in",
        "is",
        "not",
        "and",
        "or",
        "global",
        "nonlocal",
        "del",
        "yield",
        "async",
        "await",
        "c:\\",
        "windows",
        "system32",
        "program files",
        "users",
        "appdata",
        "local",
        "roaming",
        "temp",
        "desktop",
        "documents",
        "downloads",
        "http",
        "https",
        "ftp",
        "tcp",
        "udp",
        "ip",
        "port",
        "host",
        "server",
        "client",
        "connection",
        "socket",
        "address",
        "protocol",
        "version",
        "content-type",
        "user-agent",
        "accept",
        "cookie",
        "session",
        "token",
        "auth",
        "login",
        "password",
        "username",
        "email",
        "id",
        "key",
        "value",
        "name",
        "file",
        "path",
        "dir",
        "folder",
        "data",
        "text",
        "body",
        "header",
        "status",
        "code",
        "message",
        "error",
        "success",
        "fail",
        "ok",
        "cancel",
    ];
    let lower = s.to_lowercase();
    keywords.contains(&lower.as_str()) || lower.len() < 4
}

fn decrypt_candidates(
    mut candidates: Vec<Vec<u8>>,
    string_candidates: Vec<String>,
    scan_result: Option<&heuristic_decryptor::ScanResult>,
) -> Vec<String> {
    let mut decoded_candidates = Vec::new();
    for s in &string_candidates {
        for decoded in decode_base64_variants(s) {
            decoded_candidates.push(decoded);
        }
        if let Some(decoded) = decode_hex_if_match(s) {
            decoded_candidates.push(decoded);
        }
    }
    crate::log!(
        "[LinkDecryptor] Base64 decoded {} candidates",
        decoded_candidates.len()
    );
    candidates.append(&mut decoded_candidates);

    let mut found_links = Vec::new();
    let mut password_candidates = Vec::new();
    for s in &string_candidates {
        if s.len() > 6 && !is_common_keyword(s) && !password_candidates.contains(s) {
            password_candidates.push(s.clone());
        }
        let trimmed = s.trim();
        if trimmed.len() > 6
            && !is_common_keyword(trimmed)
            && !password_candidates.contains(&trimmed.to_string())
        {
            password_candidates.push(trimmed.to_string());
        }
        let cleaned = normalize_disassembly_string(s);
        if cleaned.len() > 6
            && !is_common_keyword(&cleaned)
            && !password_candidates.contains(&cleaned)
        {
            password_candidates.push(cleaned);
        }
    }

    // Sort passwords by length (descending) to prioritize long keys
    password_candidates.sort_by(|a, b| b.len().cmp(&a.len()));

    // 3. Strategy A: Direct Key Usage (Heuristic) - Only if scan_result is available
    if let Some(scan_res) = scan_result {
        // Also add potential keys from heuristic scan to password candidates
        for key_bytes in &scan_res.potential_keys {
            if let Ok(s) = String::from_utf8(key_bytes.clone()) {
                if s.len() > 6 && !password_candidates.contains(&s) {
                    // Insert at the beginning as these are high confidence
                    password_candidates.insert(0, s);
                }
            }
        }

        for (_i, candidate) in candidates.iter().enumerate() {
            if let Some(decrypted) =
                heuristic_decryptor::try_decrypt_combinations(&candidate, scan_res)
            {
                if let Ok(s) = String::from_utf8(decrypted.clone()) {
                    if is_interesting_link(&s) {
                        crate::log!(
                            "[LinkDecryptor] FOUND INTERESTING LINK (Heuristic) in candidate #{}: {}",
                            _i,
                            s
                        );
                        found_links.push(s);
                    }
                }
            }
        }
    }

    // 4. Strategy B: PBKDF2 + AES-CBC (Evo Spoofer / Stealer style)
    // Blob format: [Salt: 16] [IV: 16] [Ciphertext: ...]

    let pbkdf2_candidates: Vec<&Vec<u8>> = candidates
        .iter()
        .filter(|c| c.len() >= 32 && (c.len() - 32) % 16 == 0)
        .collect();

    crate::log!(
        "[LinkDecryptor] Checking {} candidates for PBKDF2 strategy",
        pbkdf2_candidates.len()
    );

    for (i, candidate) in pbkdf2_candidates.iter().enumerate() {
        let salt = &candidate[0..16];
        let iv = &candidate[16..32];
        let ciphertext = &candidate[32..];

        for pwd in &password_candidates {
            // Optimization: Skip very short passwords
            if pwd.len() < 4 {
                continue;
            }

            // Derive Key
            let mut key = [0u8; 32];
            // PBKDF2-HMAC-SHA256, 100000 iterations
            if pbkdf2::<Hmac<Sha256>>(pwd.as_bytes(), salt, 100000, &mut key).is_ok() {
                // Try Decrypt AES-256-CBC
                match try_decrypt_aes_cbc_256(&key, iv, ciphertext) {
                    Ok(decrypted) => {
                        // Valid padding! This is very likely the correct key.
                        // Try to decode as UTF-8
                        let s_res = String::from_utf8(decrypted.clone());
                        if let Ok(s) = s_res {
                            crate::log!(
                                "[LinkDecryptor] Decryption SUCCESS (PBKDF2) Candidate #{} with pwd '{}': {}",
                                i,
                                pwd,
                                s
                            );
                            if is_interesting_link(&s) || s.starts_with("http") {
                                crate::log!(
                                    "\n===================================================================================================="
                                );
                                crate::log!("   [SUCCESS] FOUND INTERESTING LINK (PBKDF2): {}", s);
                                crate::log!(
                                    "====================================================================================================\n"
                                );
                                found_links.push(s);
                            } else {
                                crate::log!(
                                    "[LinkDecryptor] Found valid decrypted data (not a link?): {}",
                                    s
                                );
                                if heuristic_decryptor::is_meaningful_content(decrypted.as_slice())
                                {
                                    found_links.push(s);
                                }
                            }
                        }
                    }
                    Err(_) => {
                        // Padding error, wrong key.
                    }
                }
            }
        }
    }

    found_links
}

fn collect_candidates_recursive(
    obj: &CodeObject,
    candidates: &mut Vec<Vec<u8>>,
    string_candidates: &mut Vec<String>,
) {
    for c in &obj.consts {
        match c {
            MarshalValue::String(s) => {
                // Try to decode potential Base64 strings
                if s.len() > 32 {
                    for decoded in decode_base64_variants(&s) {
                        if decoded.len() > 16 {
                            candidates.push(decoded);
                        }
                    }
                }

                // If it looks like a potential key or password
                if s.len() > 4 && s.len() < 128 && !is_common_keyword(&s) {
                    string_candidates.push(s.clone());
                }

                // Raw bytes candidate (if long enough)
                if s.len() >= 32 {
                    candidates.push(s.as_bytes().to_vec());
                }
            }
            MarshalValue::Bytes(b) => {
                if b.len() >= 32 {
                    candidates.push(b.clone());
                }
            }
            MarshalValue::Code(inner) => {
                collect_candidates_recursive(&inner, candidates, string_candidates);
            }
            MarshalValue::Tuple(inner)
            | MarshalValue::List(inner)
            | MarshalValue::Set(inner)
            | MarshalValue::FrozenSet(inner) => {
                for item in inner {
                    collect_candidates_const(item, candidates, string_candidates);
                }
            }
            _ => {}
        }
    }
}

fn collect_candidates_const(
    c: &MarshalValue,
    candidates: &mut Vec<Vec<u8>>,
    string_candidates: &mut Vec<String>,
) {
    match c {
        MarshalValue::String(s) => {
            for decoded in decode_base64_variants(&s) {
                if decoded.len() > 16 {
                    candidates.push(decoded);
                }
            }
            if s.len() > 4 && !is_common_keyword(&s) {
                string_candidates.push(s.clone());
            }
            if s.len() >= 32 {
                candidates.push(s.as_bytes().to_vec());
            }
        }
        MarshalValue::Bytes(b) => {
            if b.len() >= 32 {
                candidates.push(b.clone());
            }
        }
        MarshalValue::Code(inner) => {
            collect_candidates_recursive(&inner, candidates, string_candidates);
        }
        MarshalValue::Tuple(inner)
        | MarshalValue::List(inner)
        | MarshalValue::Set(inner)
        | MarshalValue::FrozenSet(inner) => {
            for item in inner {
                collect_candidates_const(item, candidates, string_candidates);
            }
        }
        _ => {}
    }
}

fn normalize_disassembly_string(s: &str) -> String {
    // Remove "b'", "'", etc.
    let mut out = s.to_string();
    if (out.starts_with("b'") || out.starts_with("B'")) && out.ends_with("'") {
        out = out[2..out.len() - 1].to_string();
    } else if (out.starts_with("'") || out.starts_with("\""))
        && (out.ends_with("'") || out.ends_with("\""))
    {
        out = out[1..out.len() - 1].to_string();
    }
    out
}

fn normalize_base64_input(s: &str) -> String {
    // Clean up input for Base64 decoding (remove newlines, spaces, etc.)
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

fn decode_base64_variants(s: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let clean = normalize_base64_input(s);
    if clean.len() < 8 {
        return out;
    }
    if let Ok(decoded) = general_purpose::STANDARD.decode(&clean) {
        out.push(decoded);
    }
    if let Ok(decoded) = general_purpose::STANDARD_NO_PAD.decode(&clean) {
        out.push(decoded);
    }
    if let Ok(decoded) = general_purpose::URL_SAFE.decode(&clean) {
        out.push(decoded);
    }
    if let Ok(decoded) = general_purpose::URL_SAFE_NO_PAD.decode(&clean) {
        out.push(decoded);
    }
    if clean.len() % 4 != 0 {
        let mut padded = clean.clone();
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

fn decode_hex_if_match(s: &str) -> Option<Vec<u8>> {
    let mut clean = s.trim().to_string();
    if clean.starts_with("0x") || clean.starts_with("0X") {
        clean = clean[2..].to_string();
    }
    if clean.len() < 16 || clean.len() % 2 != 0 || !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    hex::decode(clean).ok()
}

fn decode_escaped_bytes(s: &str) -> Option<Vec<u8>> {
    // Handle Python style byte escapes: \x00\x01...
    if !s.contains("\\x") {
        return None;
    }

    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() && bytes[i + 1] == b'x' {
            // Hex escape
            let hex_str = std::str::from_utf8(&bytes[i + 2..i + 4]).ok()?;
            match u8::from_str_radix(hex_str, 16) {
                Ok(b) => {
                    out.push(b);
                    i += 4;
                }
                _ => return None,
            }
        } else if bytes[i] == b'\\' && i + 1 < bytes.len() {
            // Other escapes
            let next = bytes[i + 1];
            match next {
                b'n' => {
                    out.push(b'\n');
                    i += 2;
                }
                b'r' => {
                    out.push(b'\r');
                    i += 2;
                }
                b't' => {
                    out.push(b'\t');
                    i += 2;
                }
                b'\\' => {
                    out.push(b'\\');
                    i += 2;
                }
                b'\'' | b'"' => {
                    out.push(next);
                    i += 2;
                }
                _ => {
                    out.push(next);
                    i += 2;
                }
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Some(out)
}

fn try_decrypt_aes_cbc_256(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
    let decryptor = Aes256CbcDec::new_from_slices(key, iv).map_err(|_| ())?;
    let mut buf = ciphertext.to_vec();
    // decrypt_padded_mut handles the PKCS7 unpadding.
    // If it returns Ok, the padding was correct.
    let decrypted = decryptor
        .decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buf)
        .map_err(|_| ())?;
    Ok(decrypted.to_vec())
}

fn try_decrypt_aes_cbc_128(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
    let decryptor = Aes128CbcDec::new_from_slices(key, iv).map_err(|_| ())?;
    let mut buf = ciphertext.to_vec();
    let decrypted = decryptor
        .decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buf)
        .map_err(|_| ())?;
    Ok(decrypted.to_vec())
}

fn is_interesting_link(s: &str) -> bool {
    let lower = s.to_lowercase();
    lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.contains("discord.com/api/webhooks")
        || lower.contains("discordapp.com/api/webhooks")
        || lower.contains("telegram.org")
        || lower.contains("api.ipify.org")
}

// =================================================================================================
// MANUAL DECRYPTOR (User triggered)
// =================================================================================================

pub fn manual_decrypt(input_cipher: &str, input_key: &str) -> String {
    // 1. Decode Inputs
    // Try Base64 variants and Hex for cipher
    let mut cipher_candidates = decode_base64_variants(input_cipher);
    if let Some(h) = decode_hex_if_match(input_cipher) {
        cipher_candidates.push(h);
    }
    // Also include raw bytes if valid (fallback, though unlikely for binary data in text field)
    cipher_candidates.push(input_cipher.as_bytes().to_vec());

    // For key, try Base64/Hex/Raw
    let mut key_candidates_bytes = decode_base64_variants(input_key);
    if let Some(h) = decode_hex_if_match(input_key) {
        key_candidates_bytes.push(h);
    }

    // For PBKDF2, we use the input key string as the password directly
    let key_passwords = vec![input_key.to_string(), input_key.trim().to_string()];

    for cipher_bytes in cipher_candidates.iter() {
        // Strategy A: PBKDF2 (Common in Stealer / Evo Spoofer)
        // Format: Salt[16] + IV[16] + Ciphertext
        if cipher_bytes.len() >= 32 {
            let salt = &cipher_bytes[0..16];
            let iv = &cipher_bytes[16..32];
            let ciphertext = &cipher_bytes[32..];

            for pwd in &key_passwords {
                let mut key = [0u8; 32];
                // PBKDF2-HMAC-SHA256, 100000 iterations
                if pbkdf2::<Hmac<Sha256>>(pwd.as_bytes(), salt, 100000, &mut key).is_ok() {
                    if let Ok(res) = try_decrypt_aes_cbc_256(&key, iv, ciphertext) {
                        if heuristic_decryptor::is_meaningful_content(&res) {
                            if let Ok(s) = String::from_utf8(res) {
                                return s;
                            }
                        }
                    }
                }
            }
        }

        // Strategy B: Direct Key (AES-CBC)
        // Cipher = IV[16] + Ciphertext OR Cipher = Ciphertext (if IV provided separately? for now assume IV prepended)
        if cipher_bytes.len() > 16 {
            let iv = &cipher_bytes[0..16];
            let ciphertext = &cipher_bytes[16..];

            for key_bytes in key_candidates_bytes.iter() {
                // AES-256
                if key_bytes.len() == 32 {
                    if let Ok(res) = try_decrypt_aes_cbc_256(key_bytes, iv, ciphertext) {
                        if heuristic_decryptor::is_meaningful_content(&res) {
                            if let Ok(s) = String::from_utf8(res) {
                                return s;
                            }
                        }
                    }
                }
                // AES-128
                if key_bytes.len() == 16 {
                    if let Ok(res) = try_decrypt_aes_cbc_128(key_bytes, iv, ciphertext) {
                        if heuristic_decryptor::is_meaningful_content(&res) {
                            if let Ok(s) = String::from_utf8(res) {
                                return s;
                            }
                        }
                    }
                }
            }
        }
    }

    "Error: Failed to decrypt. Please check your input and key.".to_string()
}
