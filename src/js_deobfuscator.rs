use boa_engine::{Context, Source};
use regex::Regex;
use std::fs;

#[allow(dead_code)]
pub fn deobfuscate_file(path: &str) {
    if let Ok(content) = fs::read_to_string(path) {
        let deobfuscated = deobfuscate_content(&content);
        let new_path = path.replace(".js", "_deobfuscated.js");
        let _ = fs::write(&new_path, &deobfuscated);
    }
}

#[allow(dead_code)]
fn deobfuscate_content(content: &str) -> String {
    let mut ctx = Context::default();

    // 1. Regex for the String Array
    // const _0x1234 = [...] or var _0x1234 = [...]
    // Matches: const _0xa24cd8=['...'];
    let array_re = Regex::new(r"(?s)(const|var)\s+(_0x[a-f0-9]+)\s*=\s*\[.*?\];").unwrap();

    // 2. Regex for the Shuffle IIFE
    // (function(_0x..., _0x...) { ... })(_0x..., 0x...);
    let shuffle_re =
        Regex::new(r"(?s)\(function\s*\([a-zA-Z0-9_,\s]+\)\s*\{.+?\}\)\s*\(.+?\);").unwrap();

    // 3. Regex for the Proxy Function
    // function _0x...(_0x..., _0x...) { ... }
    // Or var _0x... = function(...) { ... }
    let proxy_re = Regex::new(r"(?s)(function\s+(_0x[a-f0-9]+)|(const|var)\s+(_0x[a-f0-9]+)\s*=\s*function)\s*\([a-zA-Z0-9_,\s]+\)\s*\{.+?\}").unwrap();

    let mut preamble = String::new();
    let mut proxy_name = String::new();

    // Find Array
    if let Some(cap) = array_re.captures(content) {
        preamble.push_str(&cap[0]);
        preamble.push('\n');
        // proxy_name = cap[2].to_string(); // Usually the array name is different from proxy
    }

    // Find Shuffle
    if let Some(cap) = shuffle_re.captures(content) {
        preamble.push_str(&cap[0]);
        preamble.push('\n');
    }

    // Find Proxy
    if let Some(cap) = proxy_re.captures(content) {
        preamble.push_str(&cap[0]);
        preamble.push('\n');
        // If it matched "function name", name is group 2.
        // If it matched "var name = function", name is group 4.
        if let Some(name) = cap.get(2) {
            proxy_name = name.as_str().to_string();
        } else if let Some(name) = cap.get(4) {
            proxy_name = name.as_str().to_string();
        }
    }

    // Fallback: Use the user's observed proxy name if detection fails
    if proxy_name.is_empty() {
        // Try to find the most frequent caller like _0x3ac8(0x...)
        // For now, let's look for the alias pattern: const _0xa24cd8=_0x3ac8;
        let alias_re = Regex::new(r"const\s+(_0x[a-f0-9]+)\s*=\s*(_0x[a-f0-9]+);").unwrap();
        if let Some(cap) = alias_re.captures(content) {
            proxy_name = cap[2].to_string();
            // Also add this alias to preamble
            preamble.push_str(&cap[0]);
            preamble.push('\n');
        }
    }

    if preamble.is_empty() || proxy_name.is_empty() {
        return content.to_string();
    }

    // println!("[DEOBFUSCATOR] Identified proxy: {}", proxy_name);
    // println!("[DEOBFUSCATOR] Preamble:\n{}", preamble);

    // Execute preamble
    match ctx.eval(Source::from_bytes(preamble.as_bytes())) {
        Ok(_) => {} // Preamble executed successfully
        Err(_) => {
            // Preamble execution failed
            return content.to_string();
        }
    }

    // Replace calls
    // Pattern: _0x3ac8(0x123)
    let call_re = Regex::new(&format!(r"{}\(0x[a-f0-9]+\)", regex::escape(&proxy_name))).unwrap();

    let result = call_re.replace_all(content, |caps: &regex::Captures| {
        let call_str = &caps[0];
        // Evaluate in context
        if let Ok(res) = ctx.eval(Source::from_bytes(call_str.as_bytes())) {
            if let Ok(s_js) = res.to_string(&mut ctx) {
                let s = s_js.to_std_string_escaped();
                // Wrap in quotes
                return format!("'{}'", s.replace("'", "\\'"));
            }
        }
        call_str.to_string()
    });

    result.to_string()
}
