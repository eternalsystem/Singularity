#![allow(dead_code)]

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

#[derive(Clone, Copy, Debug)]
struct PyVer {
    major: u8,
    minor: u8,
    tag: &'static str,
    magic_u16: u16,
}

fn main() -> Result<()> {
    let out_dir = PathBuf::from(env::var("OUT_DIR").context("OUT_DIR")?);

    let versions = [
        PyVer {
            major: 3,
            minor: 8,
            tag: "v3.8.0",
            magic_u16: 3413,
        },
        PyVer {
            major: 3,
            minor: 9,
            tag: "v3.9.0",
            magic_u16: 3425,
        },
        PyVer {
            major: 3,
            minor: 10,
            tag: "v3.10.0",
            magic_u16: 3439,
        },
        PyVer {
            major: 3,
            minor: 11,
            tag: "v3.11.0",
            magic_u16: 3495,
        },
        PyVer {
            major: 3,
            minor: 12,
            tag: "v3.12.0",
            magic_u16: 3531,
        },
        PyVer {
            major: 3,
            minor: 13,
            tag: "v3.13.0",
            magic_u16: 3571,
        },
        PyVer {
            major: 3,
            minor: 14,
            tag: "v3.14.0a4", // Updated tag for consistency, though we use hardcoded magic
            magic_u16: 3660,  // Current 3.14a1+ magic number
        },
    ];

    let mut out = String::new();
    out.push_str("pub struct OpcodeTables {\n");
    out.push_str("    pub major: u8,\n");
    out.push_str("    pub minor: u8,\n");
    out.push_str("    pub magic_u16: u16,\n");
    out.push_str("    pub opname: [&'static str; 256],\n");
    out.push_str("    pub hasconst: [bool; 256],\n");
    out.push_str("    pub hasname: [bool; 256],\n");
    out.push_str("    pub hasjrel: [bool; 256],\n");
    out.push_str("    pub hasjabs: [bool; 256],\n");
    out.push_str("    pub haslocal: [bool; 256],\n");
    out.push_str("    pub hasfree: [bool; 256],\n");
    out.push_str("    pub hascompare: [bool; 256],\n");
    out.push_str("    pub inline_cache_entries: [u8; 256],\n");
    out.push_str("    pub nb_ops: &'static [&'static str],\n");
    out.push_str("    pub cmp_op: &'static [&'static str],\n");
    out.push_str("}\n\n");

    for v in versions {
        let opcode_py = load_cpython_file(v, "Lib/opcode.py")?;
        let dis_py = load_cpython_file(v, "Lib/dis.py")?;

        let opcode_metadata_py = load_cpython_file(v, "Lib/_opcode_metadata.py").ok();
        let (opmap, opname) =
            parse_opmap_and_opname_with_fallback(&opcode_py, opcode_metadata_py.as_deref())?;
        ensure_opname_complete(&opname)?;

        let opcode_metadata_h =
            load_cpython_file(v, "Include/internal/pycore_opcode_metadata.h").ok();
        let (hasconst, hasname, hasjrel, hasjabs, haslocal, hasfree) =
            if let Some(h) = opcode_metadata_h.as_deref() {
                parse_flag_arrays_from_opcode_metadata_h(h, &opmap)?
            } else {
                (
                    parse_opcode_list(&opcode_py, "hasconst", &opmap)?,
                    parse_opcode_list(&opcode_py, "hasname", &opmap)?,
                    parse_opcode_list(&opcode_py, "hasjrel", &opmap)?,
                    parse_opcode_list(&opcode_py, "hasjabs", &opmap)?,
                    parse_opcode_list(&opcode_py, "haslocal", &opmap)?,
                    parse_opcode_list(&opcode_py, "hasfree", &opmap)?,
                )
            };
        let hascompare = parse_hascompare(&opcode_py, &opmap)?;

        let inline_cache_entries = if (v.major, v.minor) >= (3, 11) {
            if let Some(h) = opcode_metadata_h.as_deref() {
                parse_inline_cache_entries(h, &opmap)?
            } else {
                let pycore_opcode_h = load_cpython_file(v, "Include/internal/pycore_opcode.h")?;
                parse_inline_cache_entries(&pycore_opcode_h, &opmap)?
            }
        } else {
            [0u8; 256]
        };

        let nb_ops = parse_nb_ops_with_fallback(&opcode_py)?;
        let cmp_op = parse_cmp_op_from_sources(&opcode_py, &dis_py)?;
        let magic_u16 = v.magic_u16;

        out.push_str(&format!(
            "pub const OPCODE_TABLES_{}_{}: OpcodeTables = OpcodeTables {{\n",
            v.major, v.minor
        ));
        out.push_str(&format!("    major: {},\n", v.major));
        out.push_str(&format!("    minor: {},\n", v.minor));
        out.push_str(&format!("    magic_u16: {magic_u16},\n"));

        out.push_str("    opname: [\n");
        for name in opname {
            out.push_str("        ");
            out.push_str(&rust_str_lit(&name));
            out.push_str(",\n");
        }
        out.push_str("    ],\n");

        out.push_str("    hasconst: ");
        out.push_str(&rust_bool_array(&hasconst));
        out.push_str(",\n");
        out.push_str("    hasname: ");
        out.push_str(&rust_bool_array(&hasname));
        out.push_str(",\n");
        out.push_str("    hasjrel: ");
        out.push_str(&rust_bool_array(&hasjrel));
        out.push_str(",\n");
        out.push_str("    hasjabs: ");
        out.push_str(&rust_bool_array(&hasjabs));
        out.push_str(",\n");
        out.push_str("    haslocal: ");
        out.push_str(&rust_bool_array(&haslocal));
        out.push_str(",\n");
        out.push_str("    hasfree: ");
        out.push_str(&rust_bool_array(&hasfree));
        out.push_str(",\n");
        out.push_str("    hascompare: ");
        out.push_str(&rust_bool_array(&hascompare));
        out.push_str(",\n");

        out.push_str("    inline_cache_entries: ");
        out.push_str(&rust_u8_array(&inline_cache_entries));
        out.push_str(",\n");

        out.push_str("    nb_ops: &[\n");
        for s in &nb_ops {
            out.push_str("        ");
            out.push_str(&rust_str_lit(s));
            out.push_str(",\n");
        }
        out.push_str("    ],\n");

        out.push_str("    cmp_op: &[\n");
        for s in &cmp_op {
            out.push_str("        ");
            out.push_str(&rust_str_lit(s));
            out.push_str(",\n");
        }
        out.push_str("    ],\n");

        out.push_str("};\n\n");
    }

    out.push_str("pub const ALL_TABLES: &'static [OpcodeTables] = &[\n");
    for v in versions {
        out.push_str(&format!("    OPCODE_TABLES_{}_{},\n", v.major, v.minor));
    }
    out.push_str("];\n");

    let out_path = out_dir.join("py_dis_tables.rs");
    fs::write(&out_path, out).with_context(|| format!("write {}", out_path.display()))?;
    println!("cargo:rerun-if-changed=build.rs");

    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        res.set_icon("Singularity.ico");
        res.compile()
            .context("failed to compile Windows resource")?;
    }

    Ok(())
}

fn load_cpython_file(v: PyVer, rel_path: &str) -> Result<String> {
    if let Ok(root) = env::var("CPYTHON_SOURCE_DIR") {
        let p = Path::new(&root).join(v.tag).join(rel_path);
        if p.exists() {
            return fs::read_to_string(&p).with_context(|| format!("read {}", p.display()));
        }
        let p2 = Path::new(&root).join(rel_path);
        if p2.exists() {
            return fs::read_to_string(&p2).with_context(|| format!("read {}", p2.display()));
        }
    }

    let url = format!(
        "https://raw.githubusercontent.com/python/cpython/{}/{}",
        v.tag, rel_path
    );
    let resp = reqwest::blocking::get(&url).with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        bail!("GET {url}: {}", resp.status());
    }
    resp.text().with_context(|| format!("read body {url}"))
}

fn parse_opmap_and_opname(opcode_py: &str) -> Result<(BTreeMap<String, u8>, Vec<String>)> {
    let mut opmap: BTreeMap<String, u8> = BTreeMap::new();
    for line in opcode_py.lines() {
        let line = strip_comment(line).trim();
        if line.is_empty() {
            continue;
        }
        if let Some((name, op)) = parse_def_op_line(line) {
            opmap.insert(name, op);
        }
    }

    if opmap.is_empty() {
        bail!("failed to parse opmap from Lib/opcode.py");
    }

    let mut opname: Vec<String> = (0..256).map(|i| format!("<{i}>")).collect();
    for (name, op) in &opmap {
        opname[*op as usize] = name.clone();
    }
    Ok((opmap, opname))
}

fn parse_opmap_and_opname_with_fallback(
    opcode_py: &str,
    opcode_metadata_py: Option<&str>,
) -> Result<(BTreeMap<String, u8>, Vec<String>)> {
    let def_opmap = parse_opmap_from_def_op(opcode_py);
    if let Some(meta) = opcode_metadata_py {
        if let Ok(meta_opmap) = parse_opmap_from_dict(meta) {
            if meta_opmap.len() > def_opmap.len() {
                return opmap_to_opname(meta_opmap);
            }
        }
    }
    if !def_opmap.is_empty() {
        return opmap_to_opname(def_opmap);
    }
    let Some(meta) = opcode_metadata_py else {
        bail!("failed to parse opmap from Lib/opcode.py");
    };
    opmap_to_opname(parse_opmap_from_dict(meta)?)
}

fn opmap_to_opname(opmap: BTreeMap<String, u8>) -> Result<(BTreeMap<String, u8>, Vec<String>)> {
    if opmap.is_empty() {
        bail!("empty opmap");
    }
    let mut opname: Vec<String> = (0..256).map(|i| format!("<{i}>")).collect();
    for (name, op) in &opmap {
        opname[*op as usize] = name.clone();
    }
    Ok((opmap, opname))
}

fn parse_opmap_from_def_op(opcode_py: &str) -> BTreeMap<String, u8> {
    let mut opmap: BTreeMap<String, u8> = BTreeMap::new();
    for line in opcode_py.lines() {
        let line = strip_comment(line).trim();
        if line.is_empty() {
            continue;
        }
        let mut s = line;
        loop {
            let pos_def = s.find("def_op(");
            let pos_other = s.find("_op(");
            let pos = match (pos_def, pos_other) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            };
            let Some(pos) = pos else {
                break;
            };
            let s2 = &s[pos..];
            if let Some((name, op, consumed)) = parse_op_call_prefix(s2) {
                opmap.insert(name, op);
                s = s2.get(consumed..).unwrap_or("");
            } else {
                s = s2.get(1..).unwrap_or("");
            }
        }
    }
    opmap
}

fn parse_opmap_from_dict(src: &str) -> Result<BTreeMap<String, u8>> {
    let key = "opmap";
    let needle = format!("{key} =");
    let start = src
        .find(&needle)
        .with_context(|| format!("{key} not found"))?;
    let mut i = start + needle.len();
    let bytes = src.as_bytes();
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'{' {
        bail!("{key}: expected '{{'");
    }
    i += 1;
    let mut depth = 1usize;
    let mut j = i;
    while j < bytes.len() {
        let c = bytes[j];
        if c == b'\'' || c == b'"' {
            let (_s, rest) = parse_py_string(&src[j..]).context("string parse")?;
            j = bytes.len().saturating_sub(rest.len());
            continue;
        }
        if c == b'{' {
            depth += 1;
        } else if c == b'}' {
            depth -= 1;
            if depth == 0 {
                let body = &src[i..j];
                return parse_opmap_dict_body(body);
            }
        }
        j += 1;
    }
    bail!("{key}: unterminated dict")
}

fn parse_opmap_dict_body(body: &str) -> Result<BTreeMap<String, u8>> {
    let mut out: BTreeMap<String, u8> = BTreeMap::new();
    let mut s = body;
    while !s.trim_start().is_empty() {
        s = s.trim_start();
        if s.starts_with('#') {
            if let Some(nl) = s.find('\n') {
                s = &s[nl + 1..];
                continue;
            } else {
                break;
            }
        }
        if !(s.starts_with('\'') || s.starts_with('"')) {
            if let Some(nl) = s.find('\n') {
                s = &s[nl + 1..];
                continue;
            } else {
                break;
            }
        }
        let (k, rest) = parse_py_string(s)?;
        let mut s2 = rest.trim_start();
        if !s2.starts_with(':') {
            bail!("opmap: expected ':'");
        }
        s2 = s2[1..].trim_start();
        let (n, rest2) = parse_py_int(s2)?;
        if n < 256 {
            out.insert(k, n as u8);
        }
        s = rest2;
        if let Some(pos) = s.find(|c| c == ',' || c == '\n') {
            s = &s[pos + 1..];
        } else {
            break;
        }
    }
    if out.is_empty() {
        bail!("opmap: empty dict");
    }
    Ok(out)
}

fn parse_op_call_prefix(s: &str) -> Option<(String, u8, usize)> {
    let s0 = s;
    let s = s.trim_start();
    let trim_consumed = s0.len().saturating_sub(s.len());
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
        i += 1;
    }
    if i == 0 || i >= bytes.len() || bytes[i] != b'(' {
        return None;
    }
    let fn_name = &s[..i];
    if fn_name != "def_op" && !fn_name.ends_with("_op") {
        return None;
    }
    let mut rest = &s[(i + 1)..];
    let (name, s_after_name) = parse_py_string(rest).ok()?;
    rest = s_after_name.trim_start();
    if !rest.starts_with(',') {
        return None;
    }
    rest = rest[1..].trim_start();
    let (num, s_after_num) = parse_py_int(rest).ok()?;
    if num > 255 {
        return None;
    }
    let consumed = trim_consumed.saturating_add(s.len().saturating_sub(s_after_num.len()));
    Some((name, num as u8, consumed))
}

fn parse_def_op_line(line: &str) -> Option<(String, u8)> {
    let (name, op, _consumed) = parse_op_call_prefix(line)?;
    Some((name, op))
}

fn parse_opcode_list(
    opcode_py: &str,
    list_name: &str,
    opmap: &BTreeMap<String, u8>,
) -> Result<[bool; 256]> {
    let mut out = [false; 256];
    let slice = match find_list_rhs(opcode_py, list_name) {
        Ok(s) => s,
        Err(_) => return Ok(out),
    };
    for tok in split_list_tokens(&slice) {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        if let Ok(v) = tok.parse::<u16>() {
            if v < 256 {
                out[v as usize] = true;
            }
            continue;
        }
        if let Some(op) = opmap.get(tok) {
            out[*op as usize] = true;
        }
    }
    Ok(out)
}

fn parse_flag_arrays_from_opcode_metadata_h(
    opcode_metadata_h: &str,
    opmap: &BTreeMap<String, u8>,
) -> Result<(
    [bool; 256],
    [bool; 256],
    [bool; 256],
    [bool; 256],
    [bool; 256],
    [bool; 256],
)> {
    let mut hasconst = [false; 256];
    let mut hasname = [false; 256];
    let mut hasjump = [false; 256];
    let mut hasfree = [false; 256];
    let mut haslocal = [false; 256];

    let bytes = opcode_metadata_h.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let Some(rel) = opcode_metadata_h[i..].find('[') else {
            break;
        };
        i += rel + 1;
        let start = i;
        while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
            i += 1;
        }
        if i == start || i >= bytes.len() || bytes[i] != b']' {
            continue;
        }
        let name = &opcode_metadata_h[start..i];
        let mut k = i + 1;
        while k < bytes.len() && bytes[k].is_ascii_whitespace() {
            k += 1;
        }
        if k + 2 >= bytes.len() || bytes[k] != b'=' {
            continue;
        }
        k += 1;
        while k < bytes.len() && bytes[k].is_ascii_whitespace() {
            k += 1;
        }
        if k >= bytes.len() || bytes[k] != b'{' {
            continue;
        }
        let block_start = k + 1;
        let Some(end_rel) = opcode_metadata_h[block_start..].find("},") else {
            i = block_start;
            continue;
        };
        let block_end = block_start + end_rel;
        let block = &opcode_metadata_h[block_start..block_end];
        i = block_end + 2;

        let Some(&op) = opmap.get(name) else {
            continue;
        };
        let idx = op as usize;
        if block.contains("HAS_CONST_FLAG") {
            hasconst[idx] = true;
        }
        if block.contains("HAS_NAME_FLAG") {
            hasname[idx] = true;
        }
        if block.contains("HAS_JUMP_FLAG") {
            hasjump[idx] = true;
        }
        if block.contains("HAS_FREE_FLAG") {
            hasfree[idx] = true;
        }
        if block.contains("HAS_LOCAL_FLAG") {
            haslocal[idx] = true;
        }
    }

    let hasjrel = hasjump;
    let hasjabs = [false; 256];
    Ok((hasconst, hasname, hasjrel, hasjabs, haslocal, hasfree))
}

fn parse_hascompare(opcode_py: &str, opmap: &BTreeMap<String, u8>) -> Result<[bool; 256]> {
    let mut out = [false; 256];
    if let Some(&op) = opmap.get("COMPARE_OP") {
        out[op as usize] = true;
        return Ok(out);
    }
    let slice = find_list_rhs(opcode_py, "hascompare").unwrap_or_default();
    if slice.is_empty() {
        return Ok(out);
    }
    for tok in split_list_tokens(&slice) {
        let tok = tok.trim();
        if let Ok(v) = tok.parse::<u16>() {
            if v < 256 {
                out[v as usize] = true;
            }
            continue;
        }
        if let Some(op) = opmap.get(tok) {
            out[*op as usize] = true;
        }
    }
    Ok(out)
}

fn parse_nb_ops(opcode_py: &str) -> Result<Vec<String>> {
    let slice = find_list_rhs(opcode_py, "_nb_ops").unwrap_or_default();
    if slice.is_empty() {
        return Ok(Vec::new());
    }
    let mut ops = Vec::new();
    let mut i = 0usize;
    let b = slice.as_bytes();
    while i < b.len() {
        if b[i] == b'\'' || b[i] == b'"' {
            let (s, rest) = parse_py_string(&slice[i..])?;
            let consumed = slice[i..].len().saturating_sub(rest.len());
            i += consumed;
            if looks_like_operator(&s) {
                ops.push(s);
            }
            continue;
        }
        i += 1;
    }
    if ops.is_empty() {
        Ok(Vec::new())
    } else {
        Ok(ops)
    }
}

fn parse_nb_ops_with_fallback(opcode_py: &str) -> Result<Vec<String>> {
    let v = parse_nb_ops(opcode_py)?;
    if !v.is_empty() {
        return Ok(v);
    }
    Ok(vec![
        "+".to_string(),
        "&".to_string(),
        "//".to_string(),
        "<<".to_string(),
        "@".to_string(),
        "*".to_string(),
        "%".to_string(),
        "|".to_string(),
        "**".to_string(),
        ">>".to_string(),
        "-".to_string(),
        "/".to_string(),
        "^".to_string(),
        "+=".to_string(),
        "&=".to_string(),
        "//=".to_string(),
        "<<=".to_string(),
        "@=".to_string(),
        "*=".to_string(),
        "%=".to_string(),
        "|=".to_string(),
        "**=".to_string(),
        ">>=".to_string(),
        "-=".to_string(),
        "/=".to_string(),
        "^=".to_string(),
    ])
}

fn looks_like_operator(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ' ')
    {
        return false;
    }
    true
}

fn parse_cmp_op_from_sources(opcode_py: &str, dis_py: &str) -> Result<Vec<String>> {
    let slice = find_seq_rhs(opcode_py, "cmp_op")
        .or_else(|_| find_seq_rhs(dis_py, "cmp_op"))
        .or_else(|_| find_seq_rhs(dis_py, "_cmp_op"))
        .unwrap_or_default();
    if slice.is_empty() {
        return Ok(Vec::new());
    }

    let mut out: Vec<String> = Vec::new();
    let mut i = 0usize;
    let b = slice.as_bytes();
    while i < b.len() {
        if b[i] == b'\'' || b[i] == b'"' {
            let (s, rest) = parse_py_string(&slice[i..])?;
            let consumed = slice[i..].len().saturating_sub(rest.len());
            i += consumed;
            out.push(s);
            continue;
        }
        i += 1;
    }
    Ok(out)
}

fn parse_magic_u16_from_pycore_magic_number_h(pycore_magic_number_h: &str) -> Result<u16> {
    for line in pycore_magic_number_h.lines() {
        let line = strip_comment(line).trim();
        if !line.starts_with("#define PYC_MAGIC_NUMBER_TOKEN") {
            continue;
        }
        let mut parts = line.split_whitespace();
        let _define = parts.next();
        let _name = parts.next();
        let val = parts
            .next()
            .context("PYC_MAGIC_NUMBER_TOKEN missing value")?;
        let token = val
            .trim_end_matches(|c: char| c == 'u' || c == 'U' || c == 'l' || c == 'L')
            .parse::<u32>()
            .context("PYC_MAGIC_NUMBER_TOKEN parse")?;
        if token > u16::MAX as u32 {
            bail!("PYC_MAGIC_NUMBER_TOKEN too large: {token}");
        }
        return Ok(token as u16);
    }
    bail!("PYC_MAGIC_NUMBER_TOKEN not found")
}

fn parse_magic_u16(bootstrap_external_py: &str) -> Result<u16> {
    let idx = bootstrap_external_py
        .find("MAGIC_NUMBER")
        .context("MAGIC_NUMBER not found")?;
    let s = &bootstrap_external_py[idx..];
    let lit_pos = s
        .find("b'")
        .or_else(|| s.find("b\""))
        .context("MAGIC_NUMBER bytes literal not found")?;
    let bytes = &s[lit_pos + 1..];
    let (raw, _rest) = parse_py_bytes(bytes)?;
    if raw.len() < 2 {
        bail!("MAGIC_NUMBER too short");
    }
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn parse_inline_cache_entries(
    pycore_opcode_h: &str,
    opmap: &BTreeMap<String, u8>,
) -> Result<[u8; 256]> {
    let mut out = [0u8; 256];
    for line in pycore_opcode_h.lines() {
        let line = strip_comment(line).trim();
        if !line.starts_with("#define INLINE_CACHE_ENTRIES_") {
            continue;
        }
        let mut parts = line.split_whitespace();
        let _define = parts.next();
        let name = parts.next().unwrap_or("");
        let val = parts.next().unwrap_or("");
        if name.is_empty() || val.is_empty() {
            continue;
        }
        let base = name.strip_prefix("INLINE_CACHE_ENTRIES_").unwrap_or(name);
        let Ok(n) = val.parse::<u16>() else {
            continue;
        };
        if n > 255 {
            continue;
        }
        if let Some(op) = opmap.get(base) {
            out[*op as usize] = n as u8;
        }
    }
    Ok(out)
}

fn find_list_rhs(src: &str, name: &str) -> Result<String> {
    let needle = format!("{name} =");
    let start = src
        .find(&needle)
        .with_context(|| format!("{name} not found"))?;
    let mut i = start + needle.len();
    let bytes = src.as_bytes();
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'[' {
        bail!("{name}: expected '['");
    }
    i += 1;
    let mut depth = 1usize;
    let mut j = i;
    while j < bytes.len() {
        let c = bytes[j];
        if c == b'\'' || c == b'"' {
            let (_s, rest) = parse_py_string(&src[j..]).context("string parse")?;
            j = bytes.len() - rest.len();
            continue;
        }
        if c == b'[' {
            depth += 1;
        } else if c == b']' {
            depth -= 1;
            if depth == 0 {
                return Ok(src[i..j].to_string());
            }
        }
        j += 1;
    }
    bail!("{name}: unterminated list")
}

fn find_seq_rhs(src: &str, name: &str) -> Result<String> {
    let needle = format!("{name} =");
    let start = src
        .find(&needle)
        .with_context(|| format!("{name} not found"))?;
    let mut i = start + needle.len();
    let bytes = src.as_bytes();
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() {
        bail!("{name}: missing rhs");
    }
    let (open, close) = match bytes[i] {
        b'[' => (b'[', b']'),
        b'(' => (b'(', b')'),
        other => bail!("{name}: expected '[' or '(', got 0x{other:02x}"),
    };
    i += 1;
    let mut depth = 1usize;
    let mut j = i;
    while j < bytes.len() {
        let c = bytes[j];
        if c == b'\'' || c == b'"' {
            let (_s, rest) = parse_py_string(&src[j..]).context("string parse")?;
            j = bytes.len().saturating_sub(rest.len());
            continue;
        }
        if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return Ok(src[i..j].to_string());
            }
        }
        j += 1;
    }
    bail!("{name}: unterminated sequence")
}

fn split_list_tokens(list_body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in list_body.split(',') {
        let p = strip_comment(part).trim();
        if !p.is_empty() {
            out.push(p.to_string());
        }
    }
    out
}

fn parse_py_int(s: &str) -> Result<(u16, &str)> {
    let mut i = 0usize;
    let b = s.as_bytes();
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == 0 {
        bail!("expected int");
    }
    let n = s[..i].parse::<u16>()?;
    Ok((n, &s[i..]))
}

fn parse_py_string(s: &str) -> Result<(String, &str)> {
    let quote = s.chars().next().context("empty string")?;
    if quote != '\'' && quote != '"' {
        bail!("expected quote");
    }
    let mut out = String::new();
    let mut i = 1usize;
    let bytes = s.as_bytes();
    while i < bytes.len() {
        let c = bytes[i];
        if c == quote as u8 {
            return Ok((out, &s[i + 1..]));
        }
        if c == b'\\' {
            if i + 1 >= bytes.len() {
                bail!("unterminated escape");
            }
            let esc = bytes[i + 1];
            match esc {
                b'\\' => out.push('\\'),
                b'\'' => out.push('\''),
                b'"' => out.push('"'),
                b'n' => out.push('\n'),
                b'r' => out.push('\r'),
                b't' => out.push('\t'),
                b'x' => {
                    if i + 3 >= bytes.len() {
                        bail!("short \\x escape");
                    }
                    let hex = &s[i + 2..i + 4];
                    let v = u8::from_str_radix(hex, 16)?;
                    out.push(v as char);
                    i += 2;
                }
                other => out.push(other as char),
            }
            i += 2;
            continue;
        }
        out.push(c as char);
        i += 1;
    }
    bail!("unterminated string")
}

fn parse_py_bytes(s: &str) -> Result<(Vec<u8>, &str)> {
    let quote = s.chars().next().context("empty bytes")?;
    if quote != '\'' && quote != '"' {
        bail!("expected quote for bytes");
    }
    let mut out = Vec::new();
    let mut i = 1usize;
    let bytes = s.as_bytes();
    while i < bytes.len() {
        let c = bytes[i];
        if c == quote as u8 {
            return Ok((out, &s[i + 1..]));
        }
        if c == b'\\' {
            if i + 1 >= bytes.len() {
                bail!("unterminated escape");
            }
            let esc = bytes[i + 1];
            match esc {
                b'\\' => out.push(b'\\'),
                b'\'' => out.push(b'\''),
                b'"' => out.push(b'"'),
                b'n' => out.push(b'\n'),
                b'r' => out.push(b'\r'),
                b't' => out.push(b'\t'),
                b'x' => {
                    if i + 3 >= bytes.len() {
                        bail!("short \\x escape");
                    }
                    let hex = &s[i + 2..i + 4];
                    let v = u8::from_str_radix(hex, 16)?;
                    out.push(v);
                    i += 2;
                }
                other => out.push(other),
            }
            i += 2;
            continue;
        }
        out.push(c);
        i += 1;
    }
    bail!("unterminated bytes")
}

fn strip_comment(s: &str) -> &str {
    let mut in_str: Option<char> = None;
    let mut prev_backslash = false;
    for (i, ch) in s.char_indices() {
        if let Some(q) = in_str {
            if prev_backslash {
                prev_backslash = false;
                continue;
            }
            if ch == '\\' {
                prev_backslash = true;
                continue;
            }
            if ch == q {
                in_str = None;
            }
            continue;
        }
        if ch == '\'' || ch == '"' {
            in_str = Some(ch);
            continue;
        }
        if ch == '#' {
            return &s[..i];
        }
    }
    s
}

fn ensure_opname_complete(opname: &[String]) -> Result<()> {
    if opname.len() != 256 {
        bail!("opname length != 256");
    }
    Ok(())
}

fn rust_str_lit(s: &str) -> String {
    let mut out = String::new();
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn rust_bool_array(a: &[bool; 256]) -> String {
    let mut out = String::new();
    out.push('[');
    for (i, v) in a.iter().enumerate() {
        if i != 0 {
            out.push_str(", ");
        }
        out.push_str(if *v { "true" } else { "false" });
    }
    out.push(']');
    out
}

fn rust_u8_array(a: &[u8; 256]) -> String {
    let mut out = String::new();
    out.push('[');
    for (i, v) in a.iter().enumerate() {
        if i != 0 {
            out.push_str(", ");
        }
        out.push_str(&v.to_string());
    }
    out.push(']');
    out
}
