use base64::prelude::*;
use eframe::egui;
use image::GenericImageView;
use serde_json::Value;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, channel};
use std::thread;

#[derive(Default, PartialEq)]
enum MiscTool {
    #[default]
    StringDecoder,
    Steganography,
}

pub struct MiscToolsState {
    selected_tool: MiscTool,

    // String Decoder State
    input_string: String,
    output_string: String,
    decode_mode: DecodeMode,

    // Steganography State
    steg_image_path: Option<PathBuf>,
    steg_result: String, // Stores raw extracted text or logs
    steg_info: String,
    steg_found_strings: Vec<String>,
    steg_metadata: Vec<(String, String)>,
    show_raw_lsb: bool,

    // Aperi'Solve Integration
    aperisolve_status: String,
    aperisolve_receiver: Option<Receiver<String>>,
}

#[derive(Default, PartialEq, Clone, Copy)]
enum DecodeMode {
    #[default]
    Hex,
    Rot13,
    Reverse,
    Base64,
    Url,
    Binary,
}

impl Default for MiscToolsState {
    fn default() -> Self {
        Self {
            selected_tool: MiscTool::StringDecoder,
            input_string: String::new(),
            output_string: String::new(),
            decode_mode: DecodeMode::Hex,
            steg_image_path: None,
            steg_result: String::new(),
            steg_info: String::new(),
            steg_found_strings: Vec::new(),
            steg_metadata: Vec::new(),
            show_raw_lsb: false,
            aperisolve_status: String::new(),
            aperisolve_receiver: None,
        }
    }
}

impl MiscToolsState {
    pub fn show(&mut self, ctx: &egui::Context, open: &mut bool) {
        // Poll for Aperi'Solve results
        if let Some(rx) = &self.aperisolve_receiver {
            if let Ok(msg) = rx.try_recv() {
                if msg.starts_with("http") {
                    self.aperisolve_status = "Opening results in browser...".to_string();
                    ctx.open_url(egui::OpenUrl::new_tab(&msg));
                    self.aperisolve_receiver = None; // Done
                } else {
                    if msg.starts_with("Error:") {
                        self.aperisolve_receiver = None;
                    }
                    self.aperisolve_status = msg; // Error or status update
                }
            }
        }

        egui::Window::new("Misc Tools")
            .open(open)
            .resize(|r| r.default_size([800.0, 600.0]))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.selectable_value(
                        &mut self.selected_tool,
                        MiscTool::StringDecoder,
                        "String Decoder",
                    );
                    ui.selectable_value(
                        &mut self.selected_tool,
                        MiscTool::Steganography,
                        "Steganography",
                    );
                });
                ui.separator();

                match self.selected_tool {
                    MiscTool::StringDecoder => self.show_string_decoder(ui),
                    MiscTool::Steganography => self.show_steganography(ui, ctx),
                }
            });
    }

    fn show_string_decoder(&mut self, ui: &mut egui::Ui) {
        ui.heading("String Decoder / Encoder");
        ui.horizontal(|ui| {
            ui.label("Mode:");
            ui.selectable_value(&mut self.decode_mode, DecodeMode::Hex, "Hex");
            ui.selectable_value(&mut self.decode_mode, DecodeMode::Rot13, "Rot13");
            ui.selectable_value(&mut self.decode_mode, DecodeMode::Reverse, "Reverse");
            ui.selectable_value(&mut self.decode_mode, DecodeMode::Base64, "Base64");
            ui.selectable_value(&mut self.decode_mode, DecodeMode::Url, "URL");
            ui.selectable_value(&mut self.decode_mode, DecodeMode::Binary, "Binary");
        });

        ui.columns(2, |columns| {
            columns[0].label("Input:");
            columns[0].add(
                egui::TextEdit::multiline(&mut self.input_string).desired_width(f32::INFINITY),
            );

            columns[1].label("Output:");
            columns[1].add(
                egui::TextEdit::multiline(&mut self.output_string).desired_width(f32::INFINITY),
            );
        });

        if ui.button("Process").clicked() {
            self.output_string = self.process_string();
        }
    }

    fn process_string(&self) -> String {
        match self.decode_mode {
            DecodeMode::Hex => {
                let cleaned: String = self
                    .input_string
                    .chars()
                    .filter(|c| c.is_ascii_hexdigit())
                    .collect();

                if let Ok(bytes) = (0..cleaned.len())
                    .step_by(2)
                    .map(|i| {
                        if i + 2 <= cleaned.len() {
                            u8::from_str_radix(&cleaned[i..i + 2], 16)
                        } else {
                            Err(std::num::ParseIntError::clone(
                                &u8::from_str_radix("GG", 16).unwrap_err(),
                            ))
                        }
                    })
                    .collect::<Result<Vec<u8>, _>>()
                {
                    String::from_utf8_lossy(&bytes).to_string()
                } else {
                    "Invalid Hex".to_string()
                }
            }
            DecodeMode::Rot13 => self
                .input_string
                .chars()
                .map(|c| match c {
                    'a'..='m' | 'A'..='M' => ((c as u8) + 13) as char,
                    'n'..='z' | 'N'..='Z' => ((c as u8) - 13) as char,
                    _ => c,
                })
                .collect(),
            DecodeMode::Reverse => self.input_string.chars().rev().collect(),
            DecodeMode::Base64 => {
                if let Ok(bytes) = BASE64_STANDARD.decode(self.input_string.trim()) {
                    String::from_utf8_lossy(&bytes).to_string()
                } else if let Ok(bytes) = BASE64_URL_SAFE.decode(self.input_string.trim()) {
                    String::from_utf8_lossy(&bytes).to_string()
                } else {
                    "Invalid Base64".to_string()
                }
            }
            DecodeMode::Url => urlencoding::decode(&self.input_string)
                .map(|s| s.to_string())
                .unwrap_or_else(|_| "Invalid URL encoding".to_string()),
            DecodeMode::Binary => {
                let cleaned: String = self
                    .input_string
                    .chars()
                    .filter(|c| *c == '0' || *c == '1')
                    .collect();
                let mut output = Vec::new();
                for i in (0..cleaned.len()).step_by(8) {
                    if i + 8 <= cleaned.len() {
                        if let Ok(byte) = u8::from_str_radix(&cleaned[i..i + 8], 2) {
                            output.push(byte);
                        }
                    }
                }
                String::from_utf8_lossy(&output).to_string()
            }
        }
    }

    fn show_steganography(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.heading("Image Steganography & Analysis");
        ui.label("Analyzes Metadata and LSB (Least Significant Bit) hidden data.");

        // Drag and Drop
        if !ctx.input(|i| i.raw.dropped_files.is_empty()) {
            let dropped = ctx.input(|i| i.raw.dropped_files.clone());
            if let Some(file) = dropped.first() {
                if let Some(path) = &file.path {
                    let ext = path
                        .extension()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_lowercase();
                    if ["png", "jpg", "jpeg", "bmp", "gif", "ico", "webp", "tiff"]
                        .contains(&ext.as_str())
                    {
                        self.load_image(path.clone());
                    }
                }
            }
        }

        ui.horizontal(|ui| {
            if ui.button("Open Image").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter(
                        "Images",
                        &["png", "jpg", "jpeg", "bmp", "gif", "ico", "webp", "tiff"],
                    )
                    .pick_file()
                {
                    self.load_image(path);
                }
            }
            if let Some(path) = &self.steg_image_path {
                ui.label(path.file_name().unwrap_or_default().to_string_lossy());
            } else {
                ui.label("No image selected (Drag & Drop supported)");
            }
        });

        ui.separator();

        if self.steg_image_path.is_some() {
            ui.horizontal(|ui| {
                if ui.button("Run Full Analysis").clicked() {
                    self.extract_lsb();
                    self.extract_metadata();
                }

                if ui.button("Analyze on Aperi'Solve (Online)").clicked() {
                    if self.aperisolve_receiver.is_none() {
                        self.start_aperisolve_upload();
                    }
                }
            });
        }

        if !self.steg_info.is_empty() {
            ui.label(egui::RichText::new(&self.steg_info).strong());
        }

        if !self.aperisolve_status.is_empty() {
            ui.label(
                egui::RichText::new(format!("Aperi'Solve: {}", self.aperisolve_status))
                    .color(egui::Color32::LIGHT_BLUE),
            );
        }

        ui.separator();

        egui::ScrollArea::vertical().show(ui, |ui| {
            if !self.steg_metadata.is_empty() {
                ui.heading("Metadata & Image Info");
                egui::Grid::new("meta_grid").striped(true).show(ui, |ui| {
                    for (k, v) in &self.steg_metadata {
                        ui.label(egui::RichText::new(k).strong());
                        ui.label(egui::RichText::new(v).color(egui::Color32::WHITE));
                        ui.end_row();
                    }
                });
                ui.separator();
            }

            ui.heading("Extracted Strings (LSB & Content)");
            if self.steg_found_strings.is_empty() {
                ui.label("No significant strings found yet. Click 'Run Full Analysis'.");
            } else {
                for s in &self.steg_found_strings {
                    ui.monospace(s);
                }
            }

            ui.separator();
            ui.checkbox(&mut self.show_raw_lsb, "Show Raw LSB Dump (Can be messy)");
            if self.show_raw_lsb {
                ui.label("Raw LSB Dump:");
                ui.add(
                    egui::TextEdit::multiline(&mut self.steg_result).desired_width(f32::INFINITY),
                );
            }
        });
    }

    fn load_image(&mut self, path: PathBuf) {
        self.steg_image_path = Some(path);
        self.steg_info = "Image loaded. Ready to analyze.".to_string();
        self.steg_result.clear();
        self.steg_found_strings.clear();
        self.steg_metadata.clear();
        self.aperisolve_status.clear();
    }

    fn start_aperisolve_upload(&mut self) {
        let Some(path) = self.steg_image_path.clone() else {
            return;
        };
        let (tx, rx) = channel();
        self.aperisolve_receiver = Some(rx);
        self.aperisolve_status = "Uploading to Aperi'Solve...".to_string();

        thread::spawn(move || {
            let client = reqwest::blocking::Client::new();

            // Prepare multipart form
            let form = match reqwest::blocking::multipart::Form::new().file("image", &path) {
                Ok(f) => f,
                Err(e) => {
                    let _ = tx.send(format!("Error: Failed to prepare file: {}", e));
                    return;
                }
            };

            // Upload
            match client
                .post("https://www.aperisolve.com/upload")
                .multipart(form)
                .send()
            {
                Ok(resp) => {
                    if resp.status().is_success() {
                        if let Ok(json) = resp.json::<Value>() {
                            if let Some(hash) = json.get("submission_hash").and_then(|h| h.as_str())
                            {
                                let url = format!("https://www.aperisolve.com/{}", hash);
                                let _ = tx.send(url);
                            } else {
                                let _ = tx.send(
                                    "Error: Invalid response from Aperi'Solve (no hash)"
                                        .to_string(),
                                );
                            }
                        } else {
                            let _ =
                                tx.send("Error: Failed to parse Aperi'Solve response".to_string());
                        }
                    } else {
                        let _ = tx.send(format!(
                            "Error: Upload failed with status {}",
                            resp.status()
                        ));
                    }
                }
                Err(e) => {
                    let _ = tx.send(format!("Error: Request failed: {}", e));
                }
            }
        });
    }

    fn extract_metadata(&mut self) {
        let Some(path) = &self.steg_image_path else {
            return;
        };
        self.steg_metadata.clear();

        // 1. Basic Image Info using image crate
        if let Ok(img) = image::open(path) {
            self.steg_metadata
                .push(("Dimensions".to_string(), format!("{:?}", img.dimensions())));
            self.steg_metadata
                .push(("Color Type".to_string(), format!("{:?}", img.color())));
        }

        // 2. EXIF Data using kamadak-exif
        if let Ok(file) = File::open(path) {
            let mut bufreader = BufReader::new(file);
            let exifreader = exif::Reader::new();
            if let Ok(exif) = exifreader.read_from_container(&mut bufreader) {
                for f in exif.fields() {
                    let val = f.display_value().with_unit(&exif).to_string();
                    if !val.is_empty() {
                        self.steg_metadata.push((f.tag.to_string(), val));
                    }
                }
            }
        }
    }

    fn extract_lsb(&mut self) {
        let Some(path) = &self.steg_image_path else {
            return;
        };

        match image::open(path) {
            Ok(img) => {
                let mut bits = Vec::new();

                // Extract bits from R, G, B channels
                for (_x, _y, pixel) in img.pixels() {
                    let rgba = pixel.0; // [u8; 4]
                    bits.push(rgba[0] & 1);
                    bits.push(rgba[1] & 1);
                    bits.push(rgba[2] & 1);
                }

                // Convert bits to bytes
                let mut bytes = Vec::new();
                for chunk in bits.chunks(8) {
                    if chunk.len() == 8 {
                        let mut byte = 0u8;
                        for (i, bit) in chunk.iter().enumerate() {
                            byte |= bit << (7 - i);
                        }
                        bytes.push(byte);
                    }
                }

                // 1. Save raw result
                self.steg_result = String::from_utf8_lossy(&bytes).chars().take(5000).collect(); // Limit to 5k chars for UI performance

                // 2. Extract Strings from LSB
                self.steg_found_strings.clear();
                self.steg_found_strings
                    .push("--- LSB Strings ---".to_string());
                let found = extract_printable_strings(&bytes, 4);
                if found.is_empty() {
                    self.steg_found_strings
                        .push("(No printable strings > 4 chars found in LSB)".to_string());
                } else {
                    self.steg_found_strings.extend(found.into_iter().take(50)); // Show top 50
                }

                // 3. Extract Strings from Raw File Content (often easier than LSB)
                if let Ok(raw_bytes) = std::fs::read(path) {
                    self.steg_found_strings
                        .push("--- File Content Strings ---".to_string());
                    let found = extract_printable_strings(&raw_bytes, 4);
                    // Filter common noise if needed, but for now just dump
                    self.steg_found_strings.extend(found.into_iter().take(50));
                }

                self.steg_info = format!("Analysis Complete. Extracted {} LSB bytes.", bytes.len());
            }
            Err(e) => {
                self.steg_info = format!("Error opening image: {}", e);
            }
        }
    }
}

fn extract_printable_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current_bytes = Vec::new();

    for &b in data {
        if b >= 32 && b <= 126 {
            // Printable ASCII
            current_bytes.push(b);
        } else {
            if current_bytes.len() >= min_len {
                if let Ok(s) = String::from_utf8(current_bytes.clone()) {
                    strings.push(s);
                }
            }
            current_bytes.clear();
        }
    }
    // Check last one
    if current_bytes.len() >= min_len {
        if let Ok(s) = String::from_utf8(current_bytes) {
            strings.push(s);
        }
    }

    strings
}
