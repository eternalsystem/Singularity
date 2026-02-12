use anyhow::{Context, Result};
use flate2::read::ZlibDecoder;
use std::path::PathBuf;

use crate::disassemble::{MarshalReader, MarshalValue, disassemble_python_blob};

#[derive(Debug, Clone)]
pub struct PyInstallerTocEntry {
    pub position: usize,
    pub compressed_size: usize,
    pub uncompressed_size: usize,
    pub compressed_flag: u8,
    pub type_code: u8,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct PyInstallerArchive {
    pub py_major: u8,
    pub py_minor: u8,
    pub entries: Vec<PyInstallerTocEntry>,
}

#[derive(Debug, Clone)]
pub struct PyInstallerExtractedEntry {
    pub name: String,
    pub payload: Vec<u8>,
    pub type_code: u8,
}

pub const PYINSTALLER_MAX_DECOMPRESSED_ENTRY_BYTES: usize = 64 * 1024 * 1024;
pub const PYINSTALLER_MAX_ENCRYPTED_STORED_BYTES: usize = 64 * 1024;

fn looks_like_pyc(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[2] == 0x0d && bytes[3] == 0x0a
}

pub fn build_pyc_header(pyver: (u8, u8), magic: Option<[u8; 4]>) -> Vec<u8> {
    let magic = magic.unwrap_or([0u8; 4]);
    let mut out = Vec::new();
    out.extend_from_slice(&magic);
    match pyver {
        (maj, min) if maj > 3 || (maj == 3 && min >= 7) => {
            out.extend_from_slice(&[0u8; 4]);
            out.extend_from_slice(&[0u8; 8]);
        }
        (maj, min) if maj > 3 || (maj == 3 && min >= 3) => {
            out.extend_from_slice(&[0u8; 4]);
            out.extend_from_slice(&[0u8; 4]);
        }
        _ => {
            out.extend_from_slice(&[0u8; 4]);
        }
    }
    out
}

fn ensure_pyc_name(name: &str) -> String {
    if name.to_ascii_lowercase().ends_with(".pyc") {
        name.to_string()
    } else {
        format!("{name}.pyc")
    }
}

pub fn looks_like_pyinstaller(bytes: &[u8]) -> bool {
    const MAGIC: &[u8] = b"MEI\x0c\x0b\x0a\x0b\x0e";
    if bytes.len() < MAGIC.len() {
        return false;
    }
    bytes.windows(MAGIC.len()).any(|window| window == MAGIC)
}

fn read_u32_be(bytes: &[u8], off: usize) -> Result<u32> {
    let end = off.saturating_add(4);
    let b: [u8; 4] = bytes
        .get(off..end)
        .context("read_u32_be: out of bounds")?
        .try_into()
        .context("read_u32_be: slice")?;
    Ok(u32::from_be_bytes(b))
}

fn read_i32_be(bytes: &[u8], off: usize) -> Result<i32> {
    Ok(read_u32_be(bytes, off)? as i32)
}

pub fn parse_pyinstaller_archive(bytes: &[u8]) -> Result<PyInstallerArchive> {
    const MAGIC: &[u8] = b"MEI\x0c\x0b\x0a\x0b\x0e";

    let file_size = bytes.len();
    let cookie_pos = bytes
        .windows(MAGIC.len())
        .rposition(|w| w == MAGIC)
        .context("PyInstaller cookie not found")?;

    fn parse_with_cookie(
        bytes: &[u8],
        cookie_pos: usize,
        cookie_size: usize,
    ) -> Result<PyInstallerArchive> {
        let (length_of_package, toc_rel, toc_len, pyver) = match cookie_size {
            24 => {
                let length_of_package = read_i32_be(bytes, cookie_pos + 8)? as i64;
                let toc_rel = read_i32_be(bytes, cookie_pos + 12)? as i64;
                let toc_len = read_i32_be(bytes, cookie_pos + 16)? as i64;
                let pyver = read_i32_be(bytes, cookie_pos + 20)? as i64;
                if length_of_package < 0 || toc_rel < 0 {
                    anyhow::bail!("invalid PyInstaller cookie (v20) values");
                }
                (length_of_package as u64, toc_rel as u64, toc_len, pyver)
            }
            88 => {
                let length_of_package = read_u32_be(bytes, cookie_pos + 8)? as u64;
                let toc_rel = read_u32_be(bytes, cookie_pos + 12)? as u64;
                let toc_len = read_i32_be(bytes, cookie_pos + 16)? as i64;
                let pyver = read_i32_be(bytes, cookie_pos + 20)? as i64;
                (length_of_package, toc_rel, toc_len, pyver)
            }
            other => anyhow::bail!("unsupported cookie size: {other}"),
        };

        let (py_major, py_minor) = if pyver >= 100 {
            ((pyver / 100) as u8, (pyver % 100) as u8)
        } else {
            ((pyver / 10) as u8, (pyver % 10) as u8)
        };

        let file_size = bytes.len() as u64;
        let tail_bytes = file_size
            .saturating_sub(cookie_pos as u64)
            .saturating_sub(cookie_size as u64);
        let overlay_size = length_of_package.saturating_add(tail_bytes);
        let overlay_pos = file_size.saturating_sub(overlay_size);

        let toc_pos = overlay_pos.saturating_add(toc_rel) as usize;
        if toc_pos >= bytes.len() {
            anyhow::bail!("PyInstaller TOC out of bounds");
        }
        let toc_size = ((toc_len.max(0)) as usize).min(bytes.len().saturating_sub(toc_pos));

        let mut entries = Vec::new();
        let mut parsed = 0usize;
        let mut idx = 0usize;
        while parsed < toc_size {
            let size_off = toc_pos.saturating_add(parsed);
            if size_off.saturating_add(4) > toc_pos.saturating_add(toc_size) {
                break;
            }
            let entry_size = read_i32_be(bytes, size_off)? as i64;
            if entry_size < 18 {
                break;
            }
            let entry_size = entry_size as usize;
            if parsed.saturating_add(entry_size) > toc_size {
                break;
            }
            let entry_off = size_off.saturating_add(4);
            let header_len = 14usize;
            let payload_len = entry_size.saturating_sub(4);
            let payload = bytes
                .get(entry_off..entry_off + payload_len)
                .context("PyInstaller TOC entry out of bounds")?;

            if payload.len() < header_len {
                parsed = parsed.saturating_add(entry_size);
                idx = idx.saturating_add(1);
                continue;
            }

            let entry_pos = u32::from_be_bytes(
                payload[0..4]
                    .try_into()
                    .context("PyInstaller TOC entry_pos")?,
            ) as u64;
            let cmprsd = u32::from_be_bytes(
                payload[4..8]
                    .try_into()
                    .context("PyInstaller TOC compressed_size")?,
            ) as usize;
            let uncmprsd = u32::from_be_bytes(
                payload[8..12]
                    .try_into()
                    .context("PyInstaller TOC uncompressed_size")?,
            ) as usize;
            let cmprs_flag = payload[12];
            let type_code = payload[13];
            let name_bytes = payload
                .get(header_len..)
                .context("PyInstaller TOC name out of bounds")?;

            let mut name = String::from_utf8_lossy(name_bytes).to_string();
            if let Some(nul) = name.find('\0') {
                name.truncate(nul);
            }
            if name.starts_with('/') {
                name = name.trim_start_matches('/').to_string();
            }
            if name.is_empty() {
                name = format!("unnamed_{idx}");
            }

            let abs_pos = overlay_pos.saturating_add(entry_pos) as usize;
            let abs_end = abs_pos.saturating_add(cmprsd);
            if abs_pos < bytes.len() && abs_end <= bytes.len() {
                entries.push(PyInstallerTocEntry {
                    position: abs_pos,
                    compressed_size: cmprsd,
                    uncompressed_size: uncmprsd,
                    compressed_flag: cmprs_flag,
                    type_code,
                    name,
                });
            }

            parsed = parsed.saturating_add(entry_size);
            idx = idx.saturating_add(1);
        }

        Ok(PyInstallerArchive {
            py_major,
            py_minor,
            entries,
        })
    }

    let mut sizes = Vec::new();
    if cookie_pos.saturating_add(88) == file_size {
        sizes.push(88);
    }
    if cookie_pos.saturating_add(24) == file_size {
        sizes.push(24);
    }
    if sizes.is_empty() {
        sizes.extend_from_slice(&[88, 24]);
    }

    for cookie_size in sizes {
        if let Ok(candidate) = parse_with_cookie(bytes, cookie_pos, cookie_size) {
            return Ok(candidate);
        }
    }

    anyhow::bail!("unable to parse PyInstaller archive cookie/TOC")
}

fn read_to_end_capped<R: std::io::Read>(mut r: R, limit: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = r.read(&mut buf).context("read")?;
        if n == 0 {
            break;
        }
        if out.len().saturating_add(n) > limit {
            anyhow::bail!("decompressed data exceeds limit ({limit} bytes)");
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

fn decompress_if_needed(entry: &PyInstallerTocEntry, data: &[u8]) -> Result<Vec<u8>> {
    if entry.compressed_flag != 1 {
        return Ok(data.to_vec());
    }
    let mut dec = ZlibDecoder::new(data);
    let mut out = Vec::with_capacity(entry.uncompressed_size.min(16 * 1024 * 1024));
    out.extend_from_slice(&read_to_end_capped(
        &mut dec,
        PYINSTALLER_MAX_DECOMPRESSED_ENTRY_BYTES,
    )?);
    Ok(out)
}

pub fn pyinstaller_entry_points(archive: &PyInstallerArchive) -> Vec<String> {
    archive
        .entries
        .iter()
        .filter(|e| e.type_code == b's')
        .map(|e| ensure_pyc_name(&e.name))
        .collect()
}

fn pyinstaller_score_entrypoint(name: &str) -> i32 {
    let lower = name.to_ascii_lowercase();
    let mut score = 0i32;

    if lower.starts_with("pyiboot") {
        score -= 1000;
    }
    if lower.starts_with("pyi_rth") {
        score -= 900;
    }
    if lower.starts_with("pyi_") {
        score -= 100;
    }
    if lower.contains("bootstrap") {
        score -= 200;
    }
    if lower.contains("pyimod") {
        score -= 200;
    }
    if lower.contains('/') || lower.contains('\\') {
        score -= 10;
    } else {
        score += 10;
    }

    if lower.ends_with(".pyc") {
        score += 1;
    }

    score
}

pub fn pyinstaller_pick_entrypoint(entrypoints: &[String]) -> Option<String> {
    if entrypoints.is_empty() {
        return None;
    }

    let mut best: Option<(&String, i32)> = None;
    for ep in entrypoints {
        let score = pyinstaller_score_entrypoint(ep);
        match best {
            None => best = Some((ep, score)),
            Some((_, best_score)) if score > best_score => best = Some((ep, score)),
            _ => {}
        }
    }

    best.map(|(s, _)| s.clone())
}

pub fn pyinstaller_extract_pysource(
    archive: &PyInstallerArchive,
    bytes: &[u8],
) -> Result<Vec<(String, Vec<u8>)>> {
    let pyver = (archive.py_major, archive.py_minor);
    let magic = pyinstaller_best_pyc_magic(archive, bytes).ok().flatten();
    let mut out = Vec::new();
    for e in archive
        .entries
        .iter()
        .filter(|e| matches!(e.type_code, b's' | b'm' | b'M'))
    {
        let start = e.position;
        let end = start.saturating_add(e.compressed_size);
        let blob = bytes
            .get(start..end)
            .with_context(|| format!("PyInstaller entry out of bounds: {}", e.name))?;
        let data = decompress_if_needed(e, blob)?;
        let mut pyc = Vec::new();
        if looks_like_pyc(&data) {
            pyc.extend_from_slice(&data);
        } else {
            pyc.extend_from_slice(&build_pyc_header(pyver, magic));
            pyc.extend_from_slice(&data);
        }
        out.push((ensure_pyc_name(&e.name), pyc));
    }
    Ok(out)
}

pub fn pyinstaller_extract_all_entries(
    archive: &PyInstallerArchive,
    bytes: &[u8],
) -> Result<Vec<PyInstallerExtractedEntry>> {
    let pyver = (archive.py_major, archive.py_minor);
    let magic = pyinstaller_best_pyc_magic(archive, bytes).ok().flatten();

    let mut out = Vec::new();
    for e in &archive.entries {
        if e.type_code == b'd' || e.type_code == b'o' {
            continue;
        }

        let start = e.position;
        let end = start.saturating_add(e.compressed_size);
        let blob = bytes
            .get(start..end)
            .with_context(|| format!("PyInstaller entry out of bounds: {}", e.name))?;
        let data = decompress_if_needed(e, blob)?;

        let (name, payload) = if e.type_code == b's' || e.type_code == b'm' || e.type_code == b'M' {
            let name = ensure_pyc_name(&e.name);
            if looks_like_pyc(&data) {
                (name, data)
            } else {
                let mut pyc = Vec::new();
                pyc.extend_from_slice(&build_pyc_header(pyver, magic));
                pyc.extend_from_slice(&data);
                (name, pyc)
            }
        } else if e.type_code == b'z' || e.type_code == b'Z' {
            let name = if e.name.to_ascii_lowercase().ends_with(".pyz") {
                e.name.clone()
            } else {
                format!("{}.pyz", e.name)
            };
            (name, data)
        } else {
            (e.name.clone(), data)
        };

        out.push(PyInstallerExtractedEntry {
            name,
            payload,
            type_code: e.type_code,
        });
    }

    Ok(out)
}

pub fn pyinstaller_pyz_pyc_magic(
    archive: &PyInstallerArchive,
    bytes: &[u8],
) -> Result<Option<[u8; 4]>> {
    for e in archive
        .entries
        .iter()
        .filter(|e| e.type_code == b'z' || e.type_code == b'Z')
    {
        let start = e.position;
        let end = start.saturating_add(e.compressed_size);
        let blob = bytes
            .get(start..end)
            .with_context(|| format!("PyInstaller PYZ entry out of bounds: {}", e.name))?;
        let pyz = decompress_if_needed(e, blob)?;
        if pyz.len() < 8 || &pyz[0..4] != b"PYZ\0" {
            continue;
        }
        let magic: [u8; 4] = pyz[4..8].try_into().unwrap();
        return Ok(Some(magic));
    }

    Ok(None)
}

pub fn pyinstaller_best_pyc_magic(
    archive: &PyInstallerArchive,
    bytes: &[u8],
) -> Result<Option<[u8; 4]>> {
    for e in archive
        .entries
        .iter()
        .filter(|e| e.type_code == b'm' || e.type_code == b'M' || e.type_code == b's')
    {
        let start = e.position;
        let end = start.saturating_add(e.compressed_size);
        let blob = bytes
            .get(start..end)
            .with_context(|| format!("PyInstaller entry out of bounds: {}", e.name))?;
        let data = decompress_if_needed(e, blob)?;
        if data.len() >= 4 && looks_like_pyc(&data) {
            let magic: [u8; 4] = data[0..4].try_into().unwrap();
            return Ok(Some(magic));
        }
    }

    pyinstaller_pyz_pyc_magic(archive, bytes)
}

#[derive(Debug, Clone)]
struct PyzTocEntry {
    is_pkg: bool,
    pos: usize,
    length: usize,
}

fn marshal_to_i64(v: &MarshalValue) -> Option<i64> {
    match v {
        MarshalValue::Int(i) => Some(*i as i64),
        MarshalValue::Int64(i) => Some(*i),
        MarshalValue::Long { value_i64, .. } => *value_i64,
        _ => None,
    }
}

fn marshal_to_string(v: &MarshalValue) -> String {
    match v {
        MarshalValue::String(s) => s.clone(),
        MarshalValue::Bytes(b) => String::from_utf8_lossy(b).to_string(),
        other => format!("{other:?}"),
    }
}

fn pyz_parse_toc(v: MarshalValue) -> Result<Vec<(String, PyzTocEntry)>> {
    let pairs: Vec<(MarshalValue, MarshalValue)> = match v {
        MarshalValue::Dict(p) => p,
        MarshalValue::List(items) => items
            .into_iter()
            .filter_map(|it| match it {
                MarshalValue::Tuple(mut t) if t.len() == 2 => {
                    let v = t.pop()?;
                    let k = t.pop()?;
                    Some((k, v))
                }
                _ => None,
            })
            .collect(),
        other => anyhow::bail!("pyz toc: unsupported marshal type: {other:?}"),
    };

    let mut out = Vec::with_capacity(pairs.len());
    for (k, v) in pairs {
        let name = marshal_to_string(&k);
        let (is_pkg, pos, length) = match v {
            MarshalValue::Tuple(t) if t.len() == 3 => {
                let is_pkg = marshal_to_i64(&t[0]).unwrap_or(0) == 1;
                let pos = marshal_to_i64(&t[1]).context("pyz toc: pos not int")?;
                let length = marshal_to_i64(&t[2]).context("pyz toc: length not int")?;
                (is_pkg, pos, length)
            }
            other => anyhow::bail!("pyz toc: invalid entry for {name}: {other:?}"),
        };

        if pos < 0 || length < 0 {
            continue;
        }
        out.push((
            name,
            PyzTocEntry {
                is_pkg,
                pos: pos as usize,
                length: length as usize,
            },
        ));
    }
    Ok(out)
}

fn pyz_extract_module(pyz: &[u8], entry: &PyzTocEntry) -> Result<Vec<u8>> {
    let start = entry.pos;
    let end = start.saturating_add(entry.length);
    let blob = pyz.get(start..end).context("pyz entry out of bounds")?;
    let mut dec = ZlibDecoder::new(blob);
    read_to_end_capped(&mut dec, PYINSTALLER_MAX_DECOMPRESSED_ENTRY_BYTES)
        .context("pyz entry zlib decompress failed")
}

#[derive(Debug, Clone)]
pub struct ExtractedPythonBlob {
    pub name: String,
    pub payload: Vec<u8>,
    pub encrypted: bool,
}

fn pyz_module_name_to_path(name: &str) -> String {
    let mut out = name.replace("..", "__");
    while out.starts_with('.') {
        out.remove(0);
    }
    if out.is_empty() {
        return "unnamed".to_string();
    }
    out.replace('.', "/")
}

pub fn pyinstaller_extract_pyz_modules_named(
    pyz_entry_name: &str,
    pyz: &[u8],
    pyver: Option<(u8, u8)>,
) -> Result<Vec<ExtractedPythonBlob>> {
    if pyz.len() < 12 || &pyz[0..4] != b"PYZ\0" {
        anyhow::bail!("invalid PYZ header");
    }

    let toc_pos = read_i32_be(pyz, 8)? as isize;
    if toc_pos < 0 {
        return Ok(Vec::new());
    }
    let toc_pos = toc_pos as usize;
    let toc_slice = pyz.get(toc_pos..).context("pyz toc out of bounds")?;
    let mut r = MarshalReader::new(toc_slice, pyver);
    let toc_obj = r.read_object().context("pyz toc marshal load")?;
    let toc = pyz_parse_toc(toc_obj)?;

    let base_dir = format!("{pyz_entry_name}_extracted");
    let mut out = Vec::with_capacity(toc.len());
    for (module_name, ent) in toc.iter() {
        let p = pyz_module_name_to_path(module_name);
        let mut extracted = pyz_extract_module_or_encrypted(pyz, ent)?;
        extracted.name = if extracted.encrypted && ent.is_pkg {
            format!("{base_dir}/{p}/__init__.pyc.encrypted")
        } else if extracted.encrypted {
            format!("{base_dir}/{p}.pyc.encrypted")
        } else if ent.is_pkg {
            format!("{base_dir}/{p}/__init__.pyc")
        } else {
            format!("{base_dir}/{p}.pyc")
        };
        out.push(extracted);
    }

    Ok(out)
}

fn pyz_extract_module_or_encrypted(pyz: &[u8], ent: &PyzTocEntry) -> Result<ExtractedPythonBlob> {
    let start = ent.pos;
    let end = start.saturating_add(ent.length);
    let blob = pyz.get(start..end).context("pyz entry out of bounds")?;
    match pyz_extract_module(pyz, ent) {
        Ok(payload) => Ok(ExtractedPythonBlob {
            name: String::new(),
            payload,
            encrypted: false,
        }),
        Err(_) => {
            let payload = blob
                .get(..blob.len().min(PYINSTALLER_MAX_ENCRYPTED_STORED_BYTES))
                .unwrap_or(blob)
                .to_vec();
            Ok(ExtractedPythonBlob {
                name: String::new(),
                payload,
                encrypted: true,
            })
        }
    }
}

pub fn pyinstaller_try_disassemble_from_pyz(
    archive: &PyInstallerArchive,
    bytes: &[u8],
    pyver: Option<(u8, u8)>,
    preferred_module: Option<&str>,
) -> Result<Option<(String, String)>> {
    let mut candidates = Vec::<String>::new();
    if let Some(m) = preferred_module {
        let m = m.trim_end_matches(".pyc").trim_end_matches(".py");
        if !m.is_empty() && !candidates.iter().any(|c| c == m) {
            candidates.push(m.to_string());
        }
    }
    if !candidates.iter().any(|c| c == "__main__") {
        candidates.push("__main__".to_string());
    }

    for e in archive
        .entries
        .iter()
        .filter(|e| e.type_code == b'z' || e.type_code == b'Z')
    {
        let start = e.position;
        let end = start.saturating_add(e.compressed_size);
        let blob = bytes
            .get(start..end)
            .with_context(|| format!("PyInstaller PYZ entry out of bounds: {}", e.name))?;
        let pyz = decompress_if_needed(e, blob)?;
        if pyz.len() < 12 || &pyz[0..4] != b"PYZ\0" {
            continue;
        }

        let toc_pos = read_i32_be(&pyz, 8)? as isize;
        if toc_pos < 0 {
            continue;
        }
        let toc_pos = toc_pos as usize;
        let toc_slice = pyz.get(toc_pos..).context("pyz toc out of bounds")?;
        let mut r = MarshalReader::new(toc_slice, pyver);
        let toc_obj = r.read_object().context("pyz toc marshal load")?;
        let toc = pyz_parse_toc(toc_obj)?;

        for want in candidates.iter() {
            if let Some((_, ent)) = toc.iter().find(|(k, _)| k == want)
                && let Ok(module_bytes) = pyz_extract_module(&pyz, ent)
                && let Ok(text) = disassemble_python_blob(&module_bytes, pyver)
            {
                return Ok(Some((want.clone(), text)));
            }
        }

        if preferred_module.is_none()
            && let Some((best_name, best_ent)) = toc.iter().find(|(k, _)| {
                let lower = k.to_ascii_lowercase();
                !lower.starts_with("pyiboot")
                    && !lower.starts_with("pyi_")
                    && !lower.contains("pyimod")
                    && !lower.contains("bootstrap")
            })
            && let Ok(module_bytes) = pyz_extract_module(&pyz, best_ent)
            && let Ok(text) = disassemble_python_blob(&module_bytes, pyver)
        {
            return Ok(Some((best_name.clone(), text)));
        }
    }

    Ok(None)
}

pub fn sanitize_rel_path(name: &str) -> PathBuf {
    let mut p = name.replace('\\', "/");
    while p.starts_with('/') {
        p.remove(0);
    }
    p = p.replace("..", "__");
    let parts = p
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|seg| {
            seg.chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect::<String>()
        })
        .collect::<Vec<_>>();
    let mut out = PathBuf::new();
    for part in parts {
        out.push(part);
    }
    if out.as_os_str().is_empty() {
        PathBuf::from("unnamed")
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_rel_path_removes_traversal() {
        let p = sanitize_rel_path("../a/../../b\\c.txt");
        assert!(!p.to_string_lossy().contains(".."));
    }
}
