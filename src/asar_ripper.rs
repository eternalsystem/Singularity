use anyhow::{Context, Result};
use serde_json::Value;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct AsarExtraction {
    pub asar_path: PathBuf,
    pub header_offset: u64,
}

fn find_subslice_positions(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            out.push(i);
            i += 1;
        } else {
            i += 1;
        }
    }
    out
}

fn validate_asar_header_at(
    file: &mut File,
    header_start: u64,
    file_len: u64,
) -> Result<Option<u32>> {
    if header_start >= file_len {
        return Ok(None);
    }
    if file_len.saturating_sub(header_start) < 16 {
        return Ok(None);
    }

    let mut header = [0u8; 16];
    file.seek(SeekFrom::Start(header_start))?;
    file.read_exact(&mut header)?;

    let magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    if magic != 4 {
        return Ok(None);
    }

    let json_size = u32::from_le_bytes([header[12], header[13], header[14], header[15]]);
    if json_size == 0 {
        return Ok(None);
    }

    let json_start = header_start.saturating_add(16);
    if (json_start as u128) + (json_size as u128) > (file_len as u128) {
        return Ok(None);
    }

    let mut json_buf = vec![0u8; json_size as usize];
    file.seek(SeekFrom::Start(json_start))?;
    file.read_exact(&mut json_buf)?;

    let json_str = match std::str::from_utf8(&json_buf) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    let v: Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };

    let has_files = v.get("files").map(|f| f.is_object()).unwrap_or(false);
    if !has_files {
        return Ok(None);
    }

    Ok(Some(json_size))
}

pub fn extract_first_appended_asar(
    exe_path: &Path,
    output_dir: &Path,
) -> Result<Option<AsarExtraction>> {
    let mut file = File::open(exe_path).with_context(|| format!("open exe: {exe_path:?}"))?;
    let file_len = file
        .metadata()
        .with_context(|| format!("stat exe: {exe_path:?}"))?
        .len();

    let chunk_size: usize = 1024 * 1024;
    let overlap: usize = 1024;
    let mut buffer = vec![0u8; chunk_size];
    let search_pattern = b"{\"files\":";

    let mut file_offset: u64 = 0;
    while file_offset < file_len {
        file.seek(SeekFrom::Start(file_offset))?;
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        let window = &buffer[..n];
        let positions = find_subslice_positions(window, search_pattern);
        for idx in positions {
            let absolute_pos = file_offset.saturating_add(idx as u64);
            if absolute_pos < 16 {
                continue;
            }
            let header_start = absolute_pos - 16;
            if let Some(_json_size) = validate_asar_header_at(&mut file, header_start, file_len)? {
                std::fs::create_dir_all(output_dir)?;
                let out_path = output_dir.join(format!("extracted_{header_start}.asar"));

                let mut out = File::create(&out_path)
                    .with_context(|| format!("create asar: {out_path:?}"))?;

                file.seek(SeekFrom::Start(header_start))?;
                std::io::copy(&mut file, &mut out)?;

                return Ok(Some(AsarExtraction {
                    asar_path: out_path,
                    header_offset: header_start,
                }));
            }
        }

        let step = (chunk_size - overlap) as u64;
        file_offset = file_offset.saturating_add(step);
    }

    Ok(None)
}
