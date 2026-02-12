use anyhow::Result;
use regex::Regex;
use std::io::Cursor;
use std::io::Read;
use std::sync::OnceLock;

/// Parses a Python byte literal string (e.g. `b'\x00\x01'`) into a byte vector.
/// Handles standard escape sequences.
pub fn parse_python_byte_literal(input: &str) -> Result<Vec<u8>, String> {
    let trimmed = input.trim();
    // Handle b'...' or '...' wrappers
    let content = if (trimmed.starts_with("b'") || trimmed.starts_with("B'"))
        && trimmed.ends_with("'")
    {
        &trimmed[2..trimmed.len() - 1]
    } else if (trimmed.starts_with("b\"") || trimmed.starts_with("B\"")) && trimmed.ends_with("\"")
    {
        &trimmed[2..trimmed.len() - 1]
    } else if trimmed.starts_with("'") && trimmed.ends_with("'") {
        &trimmed[1..trimmed.len() - 1]
    } else if trimmed.starts_with("\"") && trimmed.ends_with("\"") {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    };

    let mut out = Vec::new();
    let mut chars = content.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('x') => {
                    let h1 = chars.next().ok_or("Incomplete hex escape")?;
                    let h2 = chars.next().ok_or("Incomplete hex escape")?;
                    let s = format!("{}{}", h1, h2);
                    let b = u8::from_str_radix(&s, 16).map_err(|_| "Invalid hex escape")?;
                    out.push(b);
                }
                Some('\\') => out.push(b'\\'),
                Some('n') => out.push(b'\n'),
                Some('r') => out.push(b'\r'),
                Some('t') => out.push(b'\t'),
                Some('0') => out.push(b'\0'),
                Some(other) => out.push(other as u8),
                None => return Err("Trailing backslash".to_string()),
            }
        } else {
            out.push(c as u8);
        }
    }
    Ok(out)
}

static LZMA_REGEX: OnceLock<Regex> = OnceLock::new();
static ZLIB_REGEX: OnceLock<Regex> = OnceLock::new();

/// Scans the given content for obfuscated payload patterns (lzma, zlib) and attempts to decompress them.
/// Returns a list of (method_name, extracted_bytes).
pub fn scan_and_decompress_payloads(content: &str) -> Vec<(String, Vec<u8>)> {
    let mut results = Vec::new();

    // LZMA/XZ pattern: lzma.decompress(b'...')
    // We use (?s) to allow dot to match newlines if the payload is multiline (though usually it's one line)
    let lzma_re = LZMA_REGEX.get_or_init(|| {
        Regex::new(r"(?s)lzma\.decompress\s*\(\s*(b['\x22].*?['\x22])\s*\)")
            .expect("Invalid LZMA regex")
    });

    for cap in lzma_re.captures_iter(content) {
        if let Some(literal) = cap.get(1) {
            if let Ok(bytes) = parse_python_byte_literal(literal.as_str()) {
                // Try XZ
                let mut out = Vec::new();
                if lzma_rs::xz_decompress(&mut Cursor::new(&bytes), &mut out).is_ok() {
                    results.push(("lzma_xz".to_string(), out));
                    continue;
                }
                // Try legacy LZMA
                out.clear();
                if lzma_rs::lzma_decompress(&mut Cursor::new(&bytes), &mut out).is_ok() {
                    results.push(("lzma_legacy".to_string(), out));
                    continue;
                }
            }
        }
    }

    // ZLIB pattern: zlib.decompress(b'...')
    let zlib_re = ZLIB_REGEX.get_or_init(|| {
        Regex::new(r"(?s)zlib\.decompress\s*\(\s*(b['\x22].*?['\x22])\s*\)")
            .expect("Invalid ZLIB regex")
    });

    for cap in zlib_re.captures_iter(content) {
        if let Some(literal) = cap.get(1) {
            if let Ok(bytes) = parse_python_byte_literal(literal.as_str()) {
                // Try Zlib
                let mut out = Vec::new();
                let mut z = flate2::read::ZlibDecoder::new(&bytes[..]);
                if z.read_to_end(&mut out).is_ok() {
                    results.push(("zlib".to_string(), out));
                }
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_python_byte_literal_parsing() {
        assert_eq!(parse_python_byte_literal("b'abc'").unwrap(), b"abc");
        assert_eq!(parse_python_byte_literal("b\"abc\"").unwrap(), b"abc");
        assert_eq!(parse_python_byte_literal("'abc'").unwrap(), b"abc");
        assert_eq!(
            parse_python_byte_literal(r#"b'\x41\x42\x43'"#).unwrap(),
            b"ABC"
        );
        assert_eq!(parse_python_byte_literal(r#"b'\\'"#).unwrap(), b"\\");
        assert_eq!(parse_python_byte_literal(r#"b'\n'"#).unwrap(), b"\n");
        assert_eq!(parse_python_byte_literal(r#"b'A\x42C'"#).unwrap(), b"ABC");
        // Test trailing backslash error
        assert!(parse_python_byte_literal(r#"b'\"#).is_err());
    }
}
