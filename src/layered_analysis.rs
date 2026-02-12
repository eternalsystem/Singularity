use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
// use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LayerType {
    Encryption,
    Obfuscation,
    Encoding,
    Compression,
    Container, // e.g., PyInstaller, Zip
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layer {
    pub layer_type: LayerType,
    pub method: String,               // "AES-GCM", "Base64", "PyArmor", "Gzip"
    pub confidence: u8,               // 0-100
    pub details: String,              // "Key: X, IV: Y" or "Entropy: 7.9"
    pub guide: String,                // Guide text for the user
    pub extracted_files: Vec<String>, // Paths to files extracted from this layer
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayeredAnalysisReport {
    pub file_path: String,
    pub layers: Vec<Layer>,
    pub final_payload_type: String, // "Python Script", "PE Executable", etc.
}

impl LayeredAnalysisReport {
    pub fn new(file_path: String) -> Self {
        Self {
            file_path,
            layers: Vec::new(),
            final_payload_type: "Unknown".to_string(),
        }
    }

    pub fn add_layer(&mut self, layer: Layer) {
        self.layers.push(layer);
    }
}

// Entropy Calculation
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

// Basic Heuristics
pub fn detect_high_entropy(data: &[u8]) -> Option<Layer> {
    let entropy = calculate_entropy(data);
    if entropy > 7.5 {
        // Check for common compression headers
        // Gzip: 1f 8b
        // Zlib: 78 9c (Default), 78 01 (Low), 78 da (Best)
        // Zip: 50 4b 03 04
        // Bzip2: 42 5a 68
        // XZ: FD 37 7A 58 5A 00
        let is_compression = if data.len() > 2 {
            matches!(
                (data[0], data[1]),
                (0x1f, 0x8b) | (0x78, 0x9c) | (0x78, 0x01) | (0x78, 0xda) | (0x42, 0x5a)
            )
        } else {
            false
        } || if data.len() > 4 {
            matches!(
                (data[0], data[1], data[2], data[3]),
                (0x50, 0x4b, 0x03, 0x04) | (0xFD, 0x37, 0x7A, 0x58)
            )
        } else {
            false
        };

        if is_compression {
            return Some(Layer {
                layer_type: LayerType::Compression,
                method: "High Entropy (Compressed)".to_string(),
                confidence: 90,
                details: format!(
                    "Shannon Entropy: {:.2}. Standard compression header detected.",
                    entropy
                ),
                guide: "Standard compression detected. Use 'unzip', 'tar', or '7z' to extract."
                    .to_string(),
                extracted_files: Vec::new(),
            });
        }

        Some(Layer {
            layer_type: LayerType::Encryption,
            method: "High Entropy (Packed/Encrypted)".to_string(),
            confidence: 80,
            details: format!("Shannon Entropy: {:.2}. No standard compression headers found.", entropy),
            guide: "High entropy suggests encryption or custom packing. Check for specific file magic bytes or treat as raw encrypted data.".to_string(),
            extracted_files: Vec::new(),
        })
    } else {
        None
    }
}

use std::path::Path;

pub fn detect_encryption_keys(
    data: &[u8],
    base_path: &Path,
) -> Option<(Layer, Option<(String, Vec<u8>)>)> {
    let s = String::from_utf8_lossy(data);
    let result = crate::heuristic_decryptor::scan_text(&s);

    // Attempt decryption
    let decryption_result = crate::heuristic_decryptor::attempt_decryption(&result, base_path);

    if !result.potential_keys.is_empty()
        || !result.potential_ivs.is_empty()
        || decryption_result.is_some()
    {
        let mut details = Vec::new();
        if !result.potential_keys.is_empty() {
            details.push(format!(
                "Found {} potential keys",
                result.potential_keys.len()
            ));
        }
        if !result.potential_ivs.is_empty() {
            details.push(format!(
                "Found {} potential IVs",
                result.potential_ivs.len()
            ));
        }

        if let Some((desc, _)) = &decryption_result {
            details.push(format!("Decryption Success: {}", desc));
            if desc.contains("Webhook") {
                details.push("CRITICAL: Webhook/URL detected in decrypted payload".to_string());
            }
        }

        Some((Layer {
            layer_type: LayerType::Encryption,
            method: "Heuristic Key Discovery".to_string(),
            confidence: 90,
            details: details.join(", "),
            guide: "Potential encryption keys or IVs were found. Try using the 'Heuristic Decryptor' tool or manual decryption with these keys.".to_string(),
            extracted_files: Vec::new(),
        }, decryption_result))
    } else {
        None
    }
}

pub fn detect_base64(data: &[u8]) -> Option<Layer> {
    // Quick heuristic: check if data looks like valid base64
    // We'll check the first few bytes and the character set
    let valid_chars = data.iter().all(|&b| {
        (b >= b'A' && b <= b'Z')
            || (b >= b'a' && b <= b'z')
            || (b >= b'0' && b <= b'9')
            || b == b'+'
            || b == b'/'
            || b == b'='
            || b == b'\r'
            || b == b'\n'
    });

    if valid_chars && data.len() > 16 && data.len() % 4 == 0 {
        Some(Layer {
            layer_type: LayerType::Encoding,
            method: "Base64".to_string(),
            confidence: 90,
            details: "Content consists entirely of Base64 characters.".to_string(),
            guide: "The content appears to be Base64 encoded. You can decode it using a tool like CyberChef or the 'base64 -d' command.".to_string(),
            extracted_files: Vec::new(),
        })
    } else {
        None
    }
}

static JS_REGEXES: OnceLock<Vec<(&str, Regex, &str)>> = OnceLock::new();

fn get_js_regexes() -> &'static Vec<(&'static str, Regex, &'static str)> {
    JS_REGEXES.get_or_init(|| {
        vec![
            (
                "Obfuscator.io (String Array)",
                Regex::new(r"(?s)(const|var)\s+_0x[a-f0-9]+\s*=\s*\[.+?\];").unwrap(),
                "Found String Array pattern (const _0x... = [...])",
            ),
            (
                "Obfuscator.io (Shuffle IIFE)",
                Regex::new(r"(?s)\(function\(_0x[a-f0-9]+,\s*_0x[a-f0-9]+\)\s*\{[\s\S]+?\(_0x[a-f0-9]+,\s*0x[a-f0-9]+\)\)?;").unwrap(),
                "Found Shuffle IIFE pattern",
            ),
            (
                "Obfuscator.io (Proxy Function)",
                Regex::new(r"(?s)function\s+_0x[a-f0-9]+\(_0x[a-f0-9]+,\s*_0x[a-f0-9]+\)\s*\{").unwrap(),
                "Found Proxy Function pattern",
            ),
            (
                "JS-Confuser (Control Flow Flattening)",
                Regex::new(r"(?s)while\s*\(\s*(!!\[\]|true)\s*\)\s*\{\s*switch\s*\(").unwrap(),
                "Found Control Flow Flattening (switch inside while loop)",
            ),
             (
                "JS-Confuser (String Splitting)",
                Regex::new(r"['\x22]split['\x22]\s*\(\s*['\x22]\|['\x22]\s*\)").unwrap(),
                "Found String Splitting State Machine pattern",
            ),
            (
                "JS-Confuser (Presets/Variables)",
                Regex::new(r"__p_[a-zA-Z0-9]{4}_[a-zA-Z0-9_]+").unwrap(),
                "Found JS-Confuser variable naming pattern (__p_XXXX_name)",
            ),
            (
                "JS-Confuser (Hex/Unicode Strings)",
                Regex::new(r#"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}"#).unwrap(),
                "Found Hex/Unicode string escapes",
            ),
            (
                "JS-Confuser (Shuffle Function)",
                Regex::new(r"function\s+__p_[a-zA-Z0-9]{4}_shuffle").unwrap(),
                "Found JS-Confuser shuffle function",
            ),
            (
                "Polymorphic Obfuscator (__p_ prefix)",
                Regex::new(r"(?s)(var|const|let)\s+__p_[a-zA-Z0-9]+_").unwrap(),
                "Found Polymorphic/Custom Obfuscator pattern (prefix __p_)",
            ),
            (
                "Generic Packer (P.A.C.K.E.R)",
                Regex::new(r"eval\(function\(p,a,c,k,e,d\)").unwrap(),
                "Found P.A.C.K.E.R signature",
            ),
             (
                "JJEncode",
                Regex::new(r"[\$\+!\[\]\(\)]+").unwrap(),
                "Found JJEncode style symbols (heuristic)",
            ),
             (
                "AAEncode",
                Regex::new(r"[\u00A0-\uFFFF]+").unwrap(),
                "Found AAEncode style symbols (heuristic)",
            ),
            (
                "CryptoJS",
                Regex::new(r"CryptoJS\.(AES|DES|Rabbit|RC4|TripleDES)\.(encrypt|decrypt)").unwrap(),
                "Found CryptoJS Usage (Encryption/Decryption)",
            ),
            (
                "Web Crypto API",
                Regex::new(r"window\.crypto\.subtle\.(encrypt|decrypt|importKey)").unwrap(),
                "Found Web Crypto API Usage",
            ),
             (
                "Standard Encryption Functions",
                Regex::new(r"(AES|DES|RSA)\.(encrypt|decrypt)").unwrap(),
                "Found Standard Encryption Function Calls",
            ),
        ]
    })
}

pub fn detect_js_obfuscation(s: &str, is_pkg: bool) -> Option<Layer> {
    let mut confidence = 0;
    let mut details: Vec<String> = Vec::new();
    let mut detected_method = "Generic JS Obfuscation".to_string();

    // Specific Signature Checks
    let regexes = get_js_regexes();
    let mut obfuscator_io_matches = 0;
    let mut js_confuser_matches = 0;
    let mut encryption_matches = 0;
    let mut generic_matches = 0;

    for (name, re, desc) in regexes {
        if re.is_match(s) {
            // Heuristic scoring
            if name.contains("Obfuscator.io") {
                obfuscator_io_matches += 1;
                details.push(desc.to_string());
            } else if name.contains("Polymorphic Obfuscator") {
                confidence = std::cmp::max(confidence, 85);
                detected_method = "Polymorphic/Custom Obfuscator".to_string();
                details.push(desc.to_string());
            } else if name.contains("JS-Confuser") {
                if name.contains("Hex/Unicode") {
                    generic_matches += 1;
                    details.push(desc.to_string());
                } else {
                    js_confuser_matches += 1;
                    details.push(desc.to_string());
                }
            } else if name.contains("P.A.C.K.E.R") {
                confidence = 100;
                detected_method = "P.A.C.K.E.R".to_string();
                details.push(desc.to_string());
            } else if name.contains("JJEncode")
                && s.len() > 100
                && s.chars().all(|c| "$+![]()".contains(c))
            {
                confidence = 90;
                detected_method = "JJEncode".to_string();
                details.push("Content consists only of JJEncode characters".to_string());
            } else if name.contains("CryptoJS")
                || name.contains("Web Crypto")
                || name.contains("Standard Encryption")
            {
                encryption_matches += 1;
                details.push(desc.to_string());
            }
        }
    }

    if obfuscator_io_matches > 0 {
        confidence = std::cmp::max(confidence, 60 + (obfuscator_io_matches * 15));
        detected_method = "Obfuscator.io".to_string();
    }

    if js_confuser_matches > 0 {
        // JS-Confuser is often harder, so we give it good weight if flattened
        confidence = std::cmp::max(confidence, 70 + (js_confuser_matches * 15));
        if confidence > 80 {
            detected_method = "JS-Confuser".to_string();
        } else if detected_method == "Obfuscator.io" {
            detected_method = "Mixed Obfuscation (Obfuscator.io + Confuser)".to_string();
        } else {
            detected_method = "JS-Confuser (Probable)".to_string();
        }
    }

    if confidence == 0 && generic_matches > 0 {
        confidence = 60;
        detected_method = "Generic JS Obfuscation (Hex Strings)".to_string();
    }

    // Hex variable heuristic (backup)
    if confidence < 50 {
        let hex_vars = s.matches("_0x").count();
        if hex_vars > 20 {
            confidence = 60;
            details.push(format!(
                "High density of hex variables (_0x...): {}",
                hex_vars
            ));
            if detected_method == "Generic JS Obfuscation" {
                detected_method = "Generic Hex Obfuscation".to_string();
            }
        }
    }

    if confidence > 50 {
        if encryption_matches > 0 {
            detected_method = format!("{} + Encryption", detected_method);
            details.push("Encryption logic detected within obfuscated code".to_string());
        }

        let guide = if detected_method.contains("JS-Confuser") {
            "JS-Confuser detected. This obfuscation is extremely difficult. Automatic deobfuscation may be insufficient. Manual analysis recommended.".to_string()
        } else if is_pkg {
            "JavaScript obfuscation detected within pkg container. Automatic deobfuscation is not available for pkg snapshots.".to_string()
        } else {
            "JavaScript obfuscation detected. Automatic deobfuscation attempted. Check 'Extracted Files' for results.".to_string()
        };

        Some(Layer {
            layer_type: LayerType::Obfuscation,
            method: detected_method,
            confidence: std::cmp::min(confidence, 100),
            details: details.join(", "),
            guide,
            extracted_files: Vec::new(),
        })
    } else if encryption_matches > 0 {
        // Pure encryption detected
        Some(Layer {
            layer_type: LayerType::Encryption,
            method: "JS Encryption Logic".to_string(),
            confidence: 80,
            details: details.join(", "),
            guide: "JavaScript encryption logic detected. Look for keys and IVs in the code."
                .to_string(),
            extracted_files: Vec::new(),
        })
    } else {
        None
    }
}

pub fn detect_obfuscation(data: &[u8], is_pkg: bool) -> Option<Layer> {
    let s = String::from_utf8_lossy(data);

    // 1. Try Specific JS Detection first
    if let Some(layer) = detect_js_obfuscation(&s, is_pkg) {
        return Some(layer);
    }

    let mut confidence = 0;
    let mut details: Vec<String> = Vec::new();

    // Check for common obfuscator patterns (Legacy/Generic checks)
    if s.contains("eval(function(p,a,c,k,e,d)") {
        confidence = 100;
        details.push("Packer (P.A.C.K.E.R) detected".to_string());
    }
    if s.contains("_0x") {
        let count = s.matches("_0x").count();
        if count > 10 {
            confidence = 80;
            details.push(format!(
                "Hex variable names (_0x...) detected (count: {})",
                count
            ));
        }
    }
    if s.contains("var _0x") || s.contains("const _0x") {
        confidence = 90;
        details.push("Obfuscated variable declarations detected".to_string());
    }

    // Python specific
    if s.contains("getattr(__import__") {
        confidence += 40;
        details.push("Dynamic import usage detected".to_string());
    }
    if s.contains("lambda") && s.len() > 1000 && !s.contains("\n") {
        confidence += 30;
        details.push("Long one-liner with lambdas (possible packing)".to_string());
    }

    if confidence > 50 {
        Some(Layer {
            layer_type: LayerType::Obfuscation,
            method: "Generic Obfuscation".to_string(),
            confidence,
            details: details.join(", "),
            guide: "Obfuscation detected. Try using deobfuscators like 'js-beautify', 'synchrony' (for JS), or check for specific packer signatures.".to_string(),
            extracted_files: Vec::new(),
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_obfuscator_io_detection() {
        let sample = r#"
            var _0x5f21 = ["\x6c\x6f\x67", "hello world"];
            (function(_0x3c7e3c, _0x5f2134) {
                var _0x3c7e = function(_0x3c7e3c) {
                    while (--_0x3c7e3c) {
                        _0x3c7e3c.push(_0x3c7e3c.shift());
                    }
                };
                _0x3c7e(++_0x5f2134);
            }(_0x5f21, 0x123));
            var _0x3c7e = function(_0x3c7e3c, _0x5f2134) {
                _0x3c7e3c = _0x3c7e3c - 0x0;
                var _0x5f2134 = _0x5f21[_0x3c7e3c];
                return _0x5f2134;
            };
            console.log(_0x3c7e('0x0'));
        "#;

        let layer = detect_js_obfuscation(sample, false).expect("Should detect Obfuscator.io");
        assert_eq!(layer.method, "Obfuscator.io");
        assert!(layer.details.contains("Found String Array pattern"));
        assert!(layer.details.contains("Found Shuffle IIFE pattern"));
    }

    #[test]
    fn test_js_confuser_detection() {
        let sample = r#"
            function test() {
                var _0x1234 = "split";
                var _0x5678 = "abc|def|ghi"[_0x1234]('|');
                var _0x9abc = 0;
                while (!![]) {
                    switch (_0x5678[_0x9abc++]) {
                        case 'abc':
                            console.log('step 1');
                            continue;
                        case 'def':
                            console.log('step 2');
                            continue;
                        case 'ghi':
                            console.log('step 3');
                            continue;
                    }
                    break;
                }
            }
        "#;

        let layer = detect_js_obfuscation(sample, false).expect("Should detect JS-Confuser");
        assert!(layer.method.contains("JS-Confuser"));
        assert!(layer.details.contains("Found Control Flow Flattening"));
    }

    #[test]
    fn test_js_encryption_detection() {
        let sample = "var encrypted = CryptoJS.AES.encrypt('message', 'secret key 123');";
        let layer = detect_js_obfuscation(sample, false).expect("Should detect JS Encryption");
        assert!(matches!(layer.layer_type, LayerType::Encryption));
        assert!(layer.method.contains("JS Encryption"));
    }

    #[test]
    fn test_mixed_obfuscation_encryption() {
        // High hex var count -> Obfuscation + Encryption
        let mut obfuscated = "var _0x1 = 1; ".repeat(25);
        obfuscated.push_str("CryptoJS.AES.decrypt(data, key);");

        let layer = detect_js_obfuscation(&obfuscated, false).expect("Should detect Mixed");
        assert!(matches!(layer.layer_type, LayerType::Obfuscation));
        assert!(layer.method.contains("Encryption"));
    }

    #[test]
    fn test_polymorphic_obfuscation() {
        let sample = r#"
            var __p_Sr5m_cache, __p_T7lF_array; 
            function __p_liwJ_shuffle(arr, shift, i) { 
                arr["\x70\x75\x73\x68"](arr["\u0073\u0068\u0069\u0066\u0074"]()); 
            } 
        "#;

        let layer = detect_js_obfuscation(sample, false).expect("Should detect Obfuscation");
        // Matches JS-Confuser or our new Polymorphic regex
        assert!(layer.method.contains("Polymorphic") || layer.method.contains("JS-Confuser"));
    }
}
