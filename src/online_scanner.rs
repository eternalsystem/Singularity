use eframe::egui;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct EngineResult {
    pub name: String,
    pub scan_result: i32, // 0 = Clean, 1 = Infected, etc.
    pub threat_name: String,
}

#[derive(Clone, Debug)]
pub struct ScanResult {
    pub file_id: String,
    pub status: String,
    pub engines: Vec<EngineResult>,
    pub score: i32, // Number of detections
    pub total: i32, // Total engines
    pub permalink: String,
}

pub enum ScannerMessage {
    Status(String),
    Result(ScanResult),
    Error(String),
}

pub struct OnlineScanner {
    pub api_key: String,
    pub target_file: Option<PathBuf>,

    is_scanning: bool,
    status_message: String,
    result: Option<ScanResult>,

    tx: Sender<ScannerMessage>,
    rx: Receiver<ScannerMessage>,
}

impl Default for OnlineScanner {
    fn default() -> Self {
        let (tx, rx) = channel();
        Self {
            api_key: String::new(),
            target_file: None,
            is_scanning: false,
            status_message: "Ready to scan.".to_string(),
            result: None,
            tx,
            rx,
        }
    }
}

impl OnlineScanner {
    pub fn set_file(&mut self, path: PathBuf) {
        if self.target_file.as_ref() != Some(&path) {
            self.target_file = Some(path);
            self.result = None;
            self.status_message = "New file selected. Ready to scan.".to_string();
        }
    }

    pub fn update(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                ScannerMessage::Status(s) => self.status_message = s,
                ScannerMessage::Error(e) => {
                    self.status_message = format!("Error: {}", e);
                    self.is_scanning = false;
                }
                ScannerMessage::Result(r) => {
                    self.result = Some(r);
                    self.status_message = "Scan completed.".to_string();
                    self.is_scanning = false;
                }
            }
        }
    }

    pub fn show(&mut self, _ctx: &egui::Context, ui: &mut egui::Ui) {
        self.update();

        ui.heading(
            egui::RichText::new("Online Multi-AV Scanner (MetaDefender Cloud)")
                .color(egui::Color32::WHITE),
        );
        ui.label(
            egui::RichText::new(
                "Scans the file with 30+ antivirus engines using OPSWAT MetaDefender API.",
            )
            .color(egui::Color32::WHITE),
        );
        ui.add_space(5.0);

        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("API Key:").color(egui::Color32::WHITE));
            ui.text_edit_singleline(&mut self.api_key);
            ui.hyperlink_to("Get Free Key", "https://metadefender.opswat.com/account");
        });

        ui.add_space(10.0);

        let target_path = self.target_file.clone();
        if let Some(path) = target_path {
            egui::Frame::group(ui.style())
                .inner_margin(10.0)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new("Target File:")
                                .strong()
                                .color(egui::Color32::WHITE),
                        );
                        ui.label(
                            egui::RichText::new(
                                path.file_name().unwrap_or_default().to_string_lossy(),
                            )
                            .color(egui::Color32::WHITE),
                        );
                    });

                    ui.add_space(5.0);

                    if self.is_scanning {
                        ui.horizontal(|ui| {
                            ui.add(egui::Spinner::new());
                            ui.label(
                                egui::RichText::new(&self.status_message)
                                    .color(egui::Color32::WHITE),
                            );
                        });
                    } else {
                        ui.horizontal(|ui| {
                            if ui.button("Scan File").clicked() {
                                if self.api_key.trim().is_empty() {
                                    self.status_message = "Please enter an API Key.".to_string();
                                } else {
                                    self.start_scan(path.clone(), self.api_key.trim().to_string());
                                }
                            }
                            ui.label(
                                egui::RichText::new(&self.status_message)
                                    .color(egui::Color32::WHITE),
                            );
                        });
                    }
                });
        } else {
            ui.label(
                egui::RichText::new("No file loaded. Please open a file first.")
                    .color(egui::Color32::WHITE),
            );
        }

        ui.add_space(10.0);

        if let Some(res) = &self.result {
            // Summary Card
            egui::Frame::none()
                .fill(egui::Color32::from_gray(30))
                .rounding(5.0)
                .inner_margin(15.0)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        // Score Circle
                        let color = if res.score > 0 {
                            egui::Color32::RED
                        } else {
                            egui::Color32::GREEN
                        };
                        ui.vertical(|ui| {
                            ui.label(
                                egui::RichText::new(format!("{}/{}", res.score, res.total))
                                    .size(30.0)
                                    .color(color)
                                    .strong(),
                            );
                            ui.label(egui::RichText::new("Detections").color(egui::Color32::WHITE));
                        });

                        ui.add_space(20.0);
                        ui.separator();
                        ui.add_space(20.0);

                        ui.vertical(|ui| {
                            ui.heading(
                                egui::RichText::new("Scan Result").color(egui::Color32::WHITE),
                            );
                            ui.label(
                                egui::RichText::new(format!("Status: {}", res.status))
                                    .color(egui::Color32::WHITE),
                            );
                            ui.label(
                                egui::RichText::new(format!("File ID: {}", res.file_id))
                                    .color(egui::Color32::WHITE),
                            );
                            ui.hyperlink_to("View Full Report on MetaDefender", &res.permalink);
                        });
                    });
                });

            ui.add_space(15.0);

            // Results Table
            egui::ScrollArea::vertical().show(ui, |ui| {
                egui::Grid::new("scan_results_grid")
                    .striped(true)
                    .spacing([20.0, 8.0])
                    .min_col_width(100.0)
                    .show(ui, |ui| {
                        // Header
                        ui.label(
                            egui::RichText::new("Engine")
                                .strong()
                                .size(16.0)
                                .color(egui::Color32::WHITE),
                        );
                        ui.label(
                            egui::RichText::new("Status")
                                .strong()
                                .size(16.0)
                                .color(egui::Color32::WHITE),
                        );
                        ui.label(
                            egui::RichText::new("Threat Name")
                                .strong()
                                .size(16.0)
                                .color(egui::Color32::WHITE),
                        );
                        ui.end_row();

                        // Rows
                        for engine in &res.engines {
                            ui.label(egui::RichText::new(&engine.name).color(egui::Color32::WHITE));

                            if engine.scan_result == 1 {
                                ui.horizontal(|ui| {
                                    ui.label(
                                        egui::RichText::new("❌ Infected")
                                            .color(egui::Color32::RED)
                                            .strong(),
                                    );
                                });
                            } else {
                                ui.horizontal(|ui| {
                                    ui.label(
                                        egui::RichText::new("✅ Clean").color(egui::Color32::GREEN),
                                    );
                                });
                            }

                            if !engine.threat_name.is_empty() {
                                ui.label(
                                    egui::RichText::new(&engine.threat_name)
                                        .code()
                                        .color(egui::Color32::LIGHT_RED),
                                );
                            } else {
                                ui.label(egui::RichText::new("-").color(egui::Color32::WHITE));
                            }
                            ui.end_row();
                        }
                    });
            });
        }
    }

    fn start_scan(&mut self, path: PathBuf, api_key: String) {
        self.is_scanning = true;
        self.status_message = "Starting upload...".to_string();
        self.result = None;

        let tx = self.tx.clone();

        thread::spawn(move || match perform_scan(path, api_key, tx.clone()) {
            Ok(res) => {
                let _ = tx.send(ScannerMessage::Result(res));
            }
            Err(e) => {
                let _ = tx.send(ScannerMessage::Error(e.to_string()));
            }
        });
    }
}

fn perform_scan(
    path: PathBuf,
    api_key: String,
    tx: Sender<ScannerMessage>,
) -> anyhow::Result<ScanResult> {
    let client = reqwest::blocking::Client::new();

    // 1. Calculate Hash
    tx.send(ScannerMessage::Status(
        "Calculating file hash...".to_string(),
    ))?;
    let bytes = std::fs::read(&path)?;
    let hash = format!("{:x}", md5::compute(&bytes)).to_uppercase(); // MetaDefender uses MD5/SHA1/SHA256

    // 2. Check by Hash first
    tx.send(ScannerMessage::Status("Checking hash cache...".to_string()))?;
    let url = format!("https://api.metadefender.com/v4/hash/{}", hash);
    let resp = client.get(&url).header("apikey", &api_key).send()?;

    if resp.status().is_success() {
        let json: Value = resp.json()?;
        if let Some(_scan_results) = json.get("scan_results") {
            // Parse result directly
            return parse_results(json);
        }
    }

    // 3. Upload File
    tx.send(ScannerMessage::Status("Uploading file...".to_string()))?;
    let file_name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let resp = client
        .post("https://api.metadefender.com/v4/file")
        .header("apikey", &api_key)
        .header("filename", file_name)
        .header("content-type", "application/octet-stream")
        .body(bytes)
        .send()?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "Upload failed: {} - {}",
            resp.status(),
            resp.text().unwrap_or_default()
        );
    }

    let json: Value = resp.json()?;
    let data_id = json["data_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No data_id in response"))?;

    // 4. Poll Results
    loop {
        tx.send(ScannerMessage::Status(
            "Waiting for analysis...".to_string(),
        ))?;
        thread::sleep(Duration::from_secs(2));

        let url = format!("https://api.metadefender.com/v4/file/{}", data_id);
        let resp = client.get(&url).header("apikey", &api_key).send()?;

        if !resp.status().is_success() {
            anyhow::bail!("Polling failed: {}", resp.status());
        }

        let json: Value = resp.json()?;

        // Check progress
        let progress = json["process_info"]["progress_percentage"]
            .as_i64()
            .unwrap_or(0);
        tx.send(ScannerMessage::Status(format!("Scanning: {}%", progress)))?;

        if progress >= 100 {
            return parse_results(json);
        }
    }
}

fn parse_results(json: Value) -> anyhow::Result<ScanResult> {
    let scan_results = &json["scan_results"];
    let total = scan_results["total_avs"].as_i64().unwrap_or(0) as i32;
    let score = scan_results["total_detected_avs"].as_i64().unwrap_or(0) as i32;
    let status = scan_results["scan_all_result_a"]
        .as_str()
        .unwrap_or("Unknown")
        .to_string();
    let file_id = json["data_id"].as_str().unwrap_or("").to_string();

    let mut engines = Vec::new();
    if let Some(details) = scan_results["scan_details"].as_object() {
        for (engine_name, data) in details {
            let scan_res = data["scan_result_i"].as_i64().unwrap_or(0) as i32;
            let threat = data["threat_found"].as_str().unwrap_or("").to_string();

            engines.push(EngineResult {
                name: engine_name.clone(),
                scan_result: scan_res,
                threat_name: threat,
            });
        }
    }

    // Sort: Infected first
    engines.sort_by(|a, b| b.scan_result.cmp(&a.scan_result));

    Ok(ScanResult {
        file_id: file_id.clone(),
        status,
        engines,
        score,
        total,
        permalink: format!("https://metadefender.opswat.com/results/file/{}", file_id),
    })
}
