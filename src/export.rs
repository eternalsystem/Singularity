#![allow(dead_code)]
use crate::analysis::{AnalysisResult, extract_urls};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ExportFormat {
    Json,
    Html,
    Txt,
}

pub fn export_analysis(result: &AnalysisResult, format: ExportFormat) {
    let mut dialog = rfd::FileDialog::new().set_file_name("analysis_result");

    dialog = match format {
        ExportFormat::Json => dialog.add_filter("JSON", &["json"]),
        ExportFormat::Html => dialog.add_filter("HTML", &["html"]),
        ExportFormat::Txt => dialog.add_filter("Text", &["txt"]),
    };

    if let Some(path) = dialog.save_file() {
        let content = match format {
            ExportFormat::Json => serde_json::to_string_pretty(result).unwrap_or_default(),
            ExportFormat::Txt => format_txt(result),
            ExportFormat::Html => format_html(result),
        };

        if let Err(e) = std::fs::write(&path, content) {
            eprintln!("Failed to write export: {}", e);
        }
    }
}

fn format_txt(result: &AnalysisResult) -> String {
    let mut s = String::new();
    s.push_str(&format!("File: {}\n", result.file_path.display()));
    s.push_str(&format!("Size: {} bytes\n", result.file_size));
    s.push_str(&format!("Format: {}\n", result.file_format));
    s.push_str(&format!("Language: {}\n", result.language));
    s.push_str(&format!("Kind: {}\n", result.kind));
    if let Some(ep) = result.entry_point {
        s.push_str(&format!("Entry Point: 0x{:x}\n", ep));
    }
    if let Some(pe) = &result.python_entrypoint {
        s.push_str(&format!("Python Entrypoint: {}\n", pe));
    }

    let urls = extract_urls(result);
    if !urls.is_empty() {
        s.push_str("\n=== URLS ===\n");
        for url in urls {
            s.push_str(&format!("- {}\n", url));
        }
    }

    s.push_str("\n=== IMPORTS ===\n");
    for imp in &result.imports {
        s.push_str(&format!("- {}\n", imp));
    }

    s.push_str("\n=== SECTIONS ===\n");
    for sec in &result.sections {
        s.push_str(&format!("Name: {}\n", sec.name));
        if let Some(va) = sec.virtual_address {
            s.push_str(&format!("  Virtual Address: 0x{:x}\n", va));
        }
        if let Some(vs) = sec.virtual_size {
            s.push_str(&format!("  Virtual Size: 0x{:x}\n", vs));
        }
        if let Some(fo) = sec.file_offset {
            s.push_str(&format!("  File Offset: 0x{:x}\n", fo));
        }
        if let Some(fs) = sec.file_size {
            s.push_str(&format!("  File Size: 0x{:x}\n", fs));
        }
    }

    s.push_str("\n=== STRINGS ===\n");
    for st in &result.strings {
        s.push_str(&format!("{}\n", st));
    }

    s.push_str("\n=== DISASSEMBLY ===\n");
    if result.disassembly.is_empty() {
        let maybe_python = result.external.iter().find(|o| {
            o.tool.contains("disassemble")
                || o.tool.contains("python-dis")
                || o.tool.contains("python_dis")
        });
        if let Some(output) = maybe_python {
            s.push_str(&output.stdout);
            s.push('\n');
        } else {
            s.push_str("No disassembly available.\n");
        }
    } else {
        for line in &result.disassembly {
            s.push_str(&format!(
                "0x{:x}  {}  {} {}\n",
                line.address, line.bytes_hex, line.mnemonic, line.op_str
            ));
        }
    }

    s.push_str("\n=== DEOBFUSCATED FILES ===\n");
    for (name, content) in &result.deobfuscated_files {
        s.push_str(&format!("\n--- {} ---\n", name));
        s.push_str(content);
        s.push('\n');
    }

    s.push_str("\n=== WARNINGS ===\n");
    for w in &result.warnings {
        s.push_str(&format!("! {}\n", w));
    }

    s
}

fn format_html(result: &AnalysisResult) -> String {
    let mut s = String::new();
    s.push_str("<!DOCTYPE html><html><head><meta charset='utf-8'><title>Analysis Result</title>");
    s.push_str("<style>");
    s.push_str("body { font-family: sans-serif; background: #222; color: #eee; padding: 20px; }");
    s.push_str("h1, h2 { border-bottom: 1px solid #555; padding-bottom: 5px; }");
    s.push_str(
        ".section { background: #333; padding: 15px; margin-bottom: 20px; border-radius: 5px; }",
    );
    s.push_str("table { width: 100%; border-collapse: collapse; margin-top: 10px; }");
    s.push_str("th, td { text-align: left; padding: 8px; border-bottom: 1px solid #444; }");
    s.push_str("th { background: #444; }");
    s.push_str("pre { background: #111; padding: 10px; overflow-x: auto; }");
    s.push_str(".warning { color: #ff5555; }");
    s.push_str("</style>");
    s.push_str("</head><body>");

    s.push_str(&format!(
        "<h1>Analysis Result: {}</h1>",
        result
            .file_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
    ));

    s.push_str("<div class='section'><h2>General Info</h2>");
    s.push_str("<table>");
    s.push_str(&format!(
        "<tr><td>Path</td><td>{}</td></tr>",
        result.file_path.display()
    ));
    s.push_str(&format!(
        "<tr><td>Size</td><td>{} bytes</td></tr>",
        result.file_size
    ));
    s.push_str(&format!(
        "<tr><td>Format</td><td>{}</td></tr>",
        result.file_format
    ));
    s.push_str(&format!(
        "<tr><td>Language</td><td>{}</td></tr>",
        result.language
    ));
    s.push_str(&format!("<tr><td>Kind</td><td>{}</td></tr>", result.kind));
    if let Some(ep) = result.entry_point {
        s.push_str(&format!("<tr><td>Entry Point</td><td>0x{:x}</td></tr>", ep));
    }
    s.push_str("</table></div>");

    if !result.imports.is_empty() {
        s.push_str("<div class='section'><h2>Imports</h2><ul>");
        for imp in &result.imports {
            s.push_str(&format!("<li>{}</li>", html_escape::encode_text(imp)));
        }
        s.push_str("</ul></div>");
    }

    let urls = extract_urls(result);
    if !urls.is_empty() {
        s.push_str("<div class='section'><h2>URLs</h2><ul>");
        for url in urls {
            s.push_str(&format!(
                "<li><a href='{}' target='_blank'>{}</a></li>",
                html_escape::encode_text(&url),
                html_escape::encode_text(&url)
            ));
        }
        s.push_str("</ul></div>");
    }

    if !result.sections.is_empty() {
        s.push_str("<div class='section'><h2>Sections</h2><table><tr><th>Name</th><th>Virt Addr</th><th>Virt Size</th><th>File Offset</th><th>File Size</th></tr>");
        for sec in &result.sections {
            s.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape::encode_text(&sec.name),
                sec.virtual_address
                    .map(|v| format!("0x{:x}", v))
                    .unwrap_or_default(),
                sec.virtual_size
                    .map(|v| format!("0x{:x}", v))
                    .unwrap_or_default(),
                sec.file_offset
                    .map(|v| format!("0x{:x}", v))
                    .unwrap_or_default(),
                sec.file_size
                    .map(|v| format!("0x{:x}", v))
                    .unwrap_or_default(),
            ));
        }
        s.push_str("</table></div>");
    }

    if !result.strings.is_empty() {
        s.push_str("<div class='section'><h2>Strings</h2><pre>");
        for st in &result.strings {
            s.push_str(&format!("{}\n", html_escape::encode_text(st)));
        }
        s.push_str("</pre></div>");
    }

    let external_disasm = result.external.iter().find(|o| {
        o.tool.contains("disassemble")
            || o.tool.contains("python-dis")
            || o.tool.contains("python_dis")
    });

    if !result.disassembly.is_empty() || external_disasm.is_some() {
        s.push_str("<div class='section'><h2>Disassembly</h2>");
        if !result.disassembly.is_empty() {
            s.push_str(
                "<table><tr><th>Addr</th><th>Bytes</th><th>Mnemonic</th><th>Op Str</th></tr>",
            );
            for line in &result.disassembly {
                s.push_str(&format!(
                    "<tr><td>0x{:x}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    line.address,
                    line.bytes_hex,
                    html_escape::encode_text(&line.mnemonic),
                    html_escape::encode_text(&line.op_str)
                ));
            }
            s.push_str("</table>");
        } else if let Some(output) = external_disasm {
            s.push_str(&format!(
                "<pre>{}</pre>",
                html_escape::encode_text(&output.stdout)
            ));
        }
        s.push_str("</div>");
    }

    if !result.deobfuscated_files.is_empty() {
        s.push_str("<div class='section'><h2>Deobfuscated Files</h2>");
        for (name, content) in &result.deobfuscated_files {
            s.push_str(&format!("<h3>{}</h3>", html_escape::encode_text(name)));
            s.push_str(&format!("<pre>{}</pre>", html_escape::encode_text(content)));
        }
        s.push_str("</div>");
    }

    if !result.warnings.is_empty() {
        s.push_str("<div class='section'><h2>Warnings</h2><ul>");
        for w in &result.warnings {
            s.push_str(&format!(
                "<li class='warning'>{}</li>",
                html_escape::encode_text(w)
            ));
        }
        s.push_str("</ul></div>");
    }

    s.push_str("</body></html>");
    s
}

mod html_escape {
    pub fn encode_text(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;")
    }
}
