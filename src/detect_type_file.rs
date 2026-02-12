use std::path::Path;

pub fn detect_type_from_bytes(data: &[u8]) -> String {
    if data.len() < 4 {
        return "Unknown".to_string();
    }

    // Check for MZ (DOS Header)
    if data[0] == 0x4D && data[1] == 0x5A {
        // It's likely a PE file, check for PE signature
        // e_lfanew is at offset 0x3C (60)
        if data.len() >= 0x40 {
            let offset_bytes = &data[0x3C..0x40];
            let pe_offset = u32::from_le_bytes(offset_bytes.try_into().unwrap()) as usize;

            if data.len() >= pe_offset + 4 {
                if &data[pe_offset..pe_offset + 4] == b"PE\0\0" {
                    // Valid PE signature
                    // File Header starts at pe_offset + 4
                    // Characteristics is at offset 18 in File Header (so pe_offset + 4 + 18 = pe_offset + 22)
                    if data.len() >= pe_offset + 24 {
                        let char_offset = pe_offset + 22;
                        let characteristics =
                            u16::from_le_bytes([data[char_offset], data[char_offset + 1]]);

                        // IMAGE_FILE_DLL = 0x2000
                        if (characteristics & 0x2000) != 0 {
                            return "DLL (Dynamic Link Library)".to_string();
                        }
                        // IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
                        if (characteristics & 0x0002) != 0 {
                            return "EXE (Executable)".to_string();
                        }
                        return "PE (Unknown Type)".to_string();
                    }
                }
            }
        }
        return "DOS Executable".to_string();
    }

    // Check for ZIP
    if data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04 {
        return "ZIP Archive".to_string();
    }

    // Check for Gzip
    if data[0] == 0x1F && data[1] == 0x8B {
        return "Gzip Archive".to_string();
    }

    // Check for Zlib (Common headers)
    if data[0] == 0x78 && (data[1] == 0x01 || data[1] == 0x9C || data[1] == 0xDA) {
        return "Zlib Archive".to_string();
    }

    // Check for ELF
    if data[0] == 0x7F && data[1] == 0x45 && data[2] == 0x4C && data[3] == 0x46 {
        return "ELF Executable".to_string();
    }

    // Check for Python pyc
    // Magic numbers vary, but usually start with specific bytes depending on version
    // 3.10: 6F 0D 0D 0A
    // 3.11: A7 0D 0D 0A
    // Generic check for pyc structure might be hard with just 4 bytes,
    // but typically the timestamp follows.

    "Unknown".to_string()
}

#[allow(dead_code)]
pub fn detect_file_type(path: &Path) -> String {
    if !path.exists() {
        return "File not found".to_string();
    }

    match std::fs::read(path) {
        Ok(data) => detect_type_from_bytes(&data),
        Err(_) => "Error reading file".to_string(),
    }
}
