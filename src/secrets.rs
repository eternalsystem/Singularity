use base64::{Engine as _, engine::general_purpose};
use regex::Regex;
use serde::Serialize;
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize)]
pub struct SecretMatch {
    pub kind: String,
    pub value: String,
    pub context: String,
}

static SECRET_REGEXES: OnceLock<Vec<(String, Regex)>> = OnceLock::new();
static REVERSED_DISCORD_TOKEN: OnceLock<Regex> = OnceLock::new();
static BASE64_CANDIDATE: OnceLock<Regex> = OnceLock::new();

fn get_regexes() -> &'static Vec<(String, Regex)> {
    SECRET_REGEXES.get_or_init(|| {
        vec![
            ("Generic API Key".to_string(), Regex::new(r"(?i)(api_key|apikey|secret|token|access_key)[\s=:'\x22]+([a-zA-Z0-9_\-]{16,})").unwrap()),
            ("Google API Key".to_string(), Regex::new(r"AIza[0-9A-Za-z\\-_]{35}").unwrap()),
            ("AWS Access Key".to_string(), Regex::new(r"AKIA[0-9A-Z]{16}").unwrap()),
            ("Slack Token".to_string(), Regex::new(r"xox[baprs]-([0-9a-zA-Z]{10,48})").unwrap()),
            ("Discord Token".to_string(), Regex::new(r"[a-zA-Z0-9_-]{24,26}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,38}").unwrap()),
            ("Discord Webhook".to_string(), Regex::new(r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[a-zA-Z0-9_-]+").unwrap()),
            ("Telegram Bot Token".to_string(), Regex::new(r"\d{8,10}:[A-Za-z0-9_-]{35}").unwrap()),
            ("Private Key".to_string(), Regex::new(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----").unwrap()),
            ("Bearer Token".to_string(), Regex::new(r"Bearer\s+[a-zA-Z0-9\-\._~\+/]+=*").unwrap()),
            ("Hardcoded URL with Auth".to_string(), Regex::new(r"[a-z]+://[^/\s]+:[^@\s]+@[^/\s]+").unwrap()),
            ("Possible Token (High Entropy)".to_string(), Regex::new(r"(?i)['\x22]([a-zA-Z0-9\-_]{32,})['\x22]").unwrap()),
        ]
    })
}

fn get_reversed_token_regex() -> &'static Regex {
    REVERSED_DISCORD_TOKEN.get_or_init(|| {
        // Reversed pattern of Discord Token
        Regex::new(r"[a-zA-Z0-9_-]{27,38}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{24,26}").unwrap()
    })
}

fn get_base64_regex() -> &'static Regex {
    BASE64_CANDIDATE.get_or_init(|| {
        // Match strings that look like Base64 and are long enough to be interesting (>20 chars)
        Regex::new(r"[a-zA-Z0-9+/]{20,}={0,2}").unwrap()
    })
}

fn scan_text_internal(text: &str, matches: &mut Vec<SecretMatch>, context_prefix: &str) {
    let regexes = get_regexes();

    for (kind, re) in regexes {
        for cap in re.captures_iter(text) {
            let full_match = cap.get(0).unwrap();
            let val = if cap.len() > 1 {
                cap.get(cap.len() - 1)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_else(|| full_match.as_str().to_string())
            } else {
                full_match.as_str().to_string()
            };

            if val.len() < 8 {
                continue;
            }
            if val.contains("node_modules") || val.contains("function") || val.contains("return") {
                continue;
            }

            if kind == "Possible Token (High Entropy)" {
                let has_digit = val.chars().any(|c| c.is_ascii_digit());
                let has_alpha = val.chars().any(|c| c.is_ascii_alphabetic());
                if !has_digit || !has_alpha {
                    continue;
                }
            }

            let start = full_match.start();
            let end = full_match.end();
            let ctx_start = start.saturating_sub(30);
            let ctx_end = (end + 30).min(text.len());
            let context_snippet = text[ctx_start..ctx_end]
                .replace('\n', " ")
                .trim()
                .to_string();
            let context = if context_prefix.is_empty() {
                context_snippet
            } else {
                format!("{} {}", context_prefix, context_snippet)
            };

            matches.push(SecretMatch {
                kind: kind.clone(),
                value: val,
                context,
            });
        }
    }
}

pub fn scan_text(text: &str) -> Vec<SecretMatch> {
    let mut matches = Vec::new();

    // 1. Standard scan
    scan_text_internal(text, &mut matches, "");

    // 2. Reversed Token Scan (Heuristic)
    let rev_re = get_reversed_token_regex();
    for cap in rev_re.captures_iter(text) {
        let val = cap.get(0).unwrap().as_str();
        let reversed: String = val.chars().rev().collect();
        // Check if the reversed string matches the standard Discord Token regex to be sure
        if let Some((_, token_re)) = get_regexes().iter().find(|(k, _)| k == "Discord Token") {
            if token_re.is_match(&reversed) {
                matches.push(SecretMatch {
                    kind: "Discord Token (Reversed)".to_string(),
                    value: reversed,
                    context: format!("Found reversed: {}", val),
                });
            }
        }
    }

    // 3. Base64 / Reversed Base64 Scan (Heuristic)
    // Avoid scanning too huge files recursively
    if text.len() < 10 * 1024 * 1024 {
        let b64_re = get_base64_regex();
        for cap in b64_re.captures_iter(text) {
            let val = cap.get(0).unwrap().as_str();

            // Try Standard Decode
            if let Ok(decoded) = general_purpose::STANDARD.decode(val) {
                if let Ok(decoded_str) = std::str::from_utf8(&decoded) {
                    // Recursive scan on decoded content
                    scan_text_internal(decoded_str, &mut matches, "[Base64 Decoded]");
                }
            }

            // Try Reverse -> Decode
            let reversed_val: String = val.chars().rev().collect();
            if let Ok(decoded) = general_purpose::STANDARD.decode(&reversed_val) {
                if let Ok(decoded_str) = std::str::from_utf8(&decoded) {
                    scan_text_internal(decoded_str, &mut matches, "[Reversed Base64 Decoded]");
                }
            }
        }
    }

    // Deduplicate
    matches.sort_by(|a, b| a.value.cmp(&b.value));
    matches.dedup_by(|a, b| a.value == b.value);

    matches
}
