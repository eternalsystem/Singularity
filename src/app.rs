use crate::analysis::{AnalysisEngine, AnalysisProgress, AnalysisResult, extract_urls};
// use crate::export::{ExportFormat, export_analysis};
use crate::js_sandbox_ui::JsSandboxUi;
use crate::misc_tools::MiscToolsState;
use crate::online_scanner::OnlineScanner;
use crate::projects::{ProjectAction, ProjectsState};
use crate::tools_manager::{InstallationStatus, ToolManager};
use eframe::egui;
use std::backtrace::Backtrace;
use std::io::Write;
use std::path::PathBuf;
// use std::process::Command;
use serde_json::json;
use std::sync::mpsc;
use std::{fs::File, io::Read, io::Seek, io::SeekFrom, path::Path};

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum ViewMode {
    Original,
    Deobfuscated,
}

#[derive(Default)]
pub struct Tabs {
    pub selected: usize,
}

#[derive(Default)]
pub struct CodeViewerState {
    pub file_selected: usize,
    pub code_name: String,
    pub code_cache: String,
    pub full_content: String, // Stores the complete file content
    pub loaded_limit: usize,  // How many bytes are currently loaded
    pub chunk_size: usize,    // Size of each chunk to load
    pub line_indices: Vec<usize>,
    pub view_mode: Option<ViewMode>,
    pub search_query: String,
    pub last_search_query: String,
    pub cached_search_result: String,
    pub filtered_lines: Option<Vec<usize>>,

    // Manual Link Decryptor State
    pub show_manual_decryptor: bool,
    pub manual_input_link: String,
    pub manual_input_key: String,
    pub manual_output: String,
}

impl CodeViewerState {
    pub fn update_line_indices(&mut self) {
        self.line_indices.clear();
        if self.code_cache.is_empty() {
            return;
        }
        self.line_indices.push(0);
        for (i, byte) in self.code_cache.bytes().enumerate() {
            if byte == b'\n' {
                self.line_indices.push(i + 1);
            }
        }
    }

    pub fn set_content(&mut self, content: String) {
        self.full_content = content;
        self.chunk_size = 100 * 1024; // 100KB chunks
        self.loaded_limit = 0;
        self.code_cache.clear();

        self.load_more();

        self.search_query.clear();
        self.last_search_query.clear();
        self.cached_search_result.clear();
        self.filtered_lines = None;
    }

    pub fn load_more(&mut self) {
        if self.loaded_limit >= self.full_content.len() {
            return;
        }

        let start = self.loaded_limit;
        let remaining = self.full_content.len() - start;
        let mut end = start + self.chunk_size.min(remaining);

        // Try to find a newline to cut cleanly, but only if we are not at the very end
        if end < self.full_content.len() {
            // Search backwards from end in the current slice
            // We need to access full_content[start..end]
            if let Some(slice) = self.full_content.get(start..end) {
                if let Some(pos) = slice.rfind('\n') {
                    // Only cut if we don't lose too much (e.g. keep at least 50% of the chunk)
                    if pos > slice.len() / 2 {
                        end = start + pos + 1;
                    }
                }
            }
        }

        let chunk = &self.full_content[start..end];
        self.code_cache.push_str(chunk);
        self.loaded_limit = end;
        self.update_line_indices();
    }
}

#[derive(Default)]
pub struct SendReportState {
    pub webhook_url: String,
    pub message: String,
    pub include_embeds: bool,
    pub custom_embed_json: String,
    pub image_path: Option<PathBuf>,
    pub status_message: Option<String>,
}

#[derive(Default)]
pub struct SingularityApp {
    current_path: Option<PathBuf>,
    detected_type: Option<String>,
    detected_language: Option<String>,
    last_result: Option<AnalysisResult>,
    last_error: Option<String>,
    warnings: Vec<String>,
    analysis_rx: Option<mpsc::Receiver<Result<AnalysisResult, String>>>,
    progress_rx: Option<mpsc::Receiver<AnalysisProgress>>,
    progress: Option<AnalysisProgress>,
    running: bool,
    // installation_acknowledged: bool,
    tabs: Tabs,
    code_viewer: CodeViewerState,
    string_search_query: String,
    disassembly_search_query: String,
    processing_start_time: Option<std::time::Instant>,
    waiting_for_tools_to_rescan: bool,
    misc_tools: MiscToolsState,
    show_misc_window: bool,
    projects_state: ProjectsState,
    send_report_state: SendReportState,
    report_status_rx: Option<mpsc::Receiver<String>>,
    online_scanner: OnlineScanner,
    js_sandbox_ui: JsSandboxUi,
    signature_engine: crate::signature_engine::SignatureEngine,
    yara_consent: Option<bool>,
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct AppConfig {
    yara_consent: Option<bool>,
}

impl AppConfig {
    fn load() -> Self {
        if let Ok(appdata) = std::env::var("APPDATA") {
            let path = std::path::PathBuf::from(appdata)
                .join("Singularity")
                .join("config.json");
            if path.exists() {
                if let Ok(file) = std::fs::File::open(path) {
                    if let Ok(config) = serde_json::from_reader(file) {
                        return config;
                    }
                }
            }
        }
        Self::default()
    }

    fn save(&self) {
        if let Ok(appdata) = std::env::var("APPDATA") {
            let dir = std::path::PathBuf::from(appdata).join("Singularity");
            let _ = std::fs::create_dir_all(&dir);
            let path = dir.join("config.json");
            if let Ok(file) = std::fs::File::create(path) {
                let _ = serde_json::to_writer_pretty(file, self);
            }
        }
    }
}

fn has_python_extracted_code(result: &AnalysisResult) -> bool {
    result.deobfuscated_files.iter().any(|(name, _)| {
        name.contains("PYZ/")
            || name.contains(".pyc")
            || name.ends_with(".dis.txt")
            || name.ends_with(".pyc.encrypted.txt")
            || name.ends_with(".pyc.encrypted")
    })
}

fn is_python_pyz_related(name: &str) -> bool {
    let n = name.replace('\\', "/");
    if n.contains("PYZ/") {
        return true;
    }
    for seg in n.split('/').filter(|s| !s.is_empty()) {
        let lower = seg.to_ascii_lowercase();
        if seg == "PYZ" || lower.ends_with(".pyz_extracted") {
            return true;
        }
    }
    false
}

impl SingularityApp {
    pub fn load_settings(&mut self) {
        let config = AppConfig::load();
        self.yara_consent = config.yara_consent;
    }

    pub fn start_background_tasks(&self) {
        let rules_dir = if let Ok(appdata) = std::env::var("APPDATA") {
            std::path::PathBuf::from(appdata)
                .join("Singularity")
                .join("signatures")
        } else {
            std::path::PathBuf::from("signatures")
        };

        if self.yara_consent == Some(true) {
            let updater =
                crate::update_rules::RulesUpdater::new(self.signature_engine.clone(), rules_dir);
            updater.start_background_loop();
        } else {
            // Even if consent is not given yet, we might want to load existing rules if they exist?
            // The user said "if he doesn't want, we don't do it".
            // But if rules are already there (e.g. from previous manual install), should we load them?
            // Assuming "don't do it" means don't download/update.
            // But we can probably try to load local rules if they exist, but maybe safe to just wait.
            // Let's stick to: if Some(true), we run updater (which loads rules).
            // If we don't run updater, we should still try to load rules manually if we want them?
            // The updater loads rules after update.
            // Let's add a manual load here if consent is true but we are not running updater?
            // No, updater runs loop.

            // If consent is Some(true), updater starts and does its job.
            // If consent is None or Some(false), we do nothing.
        }
    }

    fn start_analysis(&mut self, path: PathBuf) {
        let (tx, rx) = mpsc::channel();
        let (ptx, prx) = mpsc::channel();
        self.current_path = Some(path.clone());
        self.online_scanner.set_file(path.clone());
        let (det_type, det_lang) = detect_basic(&path);
        self.detected_type = Some(det_type);
        self.detected_language = Some(det_lang);
        self.last_result = None;
        self.last_error = None;
        self.warnings.clear();

        self.code_viewer = CodeViewerState::default();
        self.code_viewer.view_mode = Some(ViewMode::Original);

        self.string_search_query.clear();
        self.disassembly_search_query.clear();
        self.analysis_rx = Some(rx);
        self.progress_rx = Some(prx);
        self.progress = None;
        self.running = true;
        self.processing_start_time = Some(std::time::Instant::now());
        self.waiting_for_tools_to_rescan = false;

        let signature_engine = self.signature_engine.clone();
        std::thread::spawn(move || {
            let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let engine = AnalysisEngine::with_default_analyzers()
                    .with_signature_engine(signature_engine);
                let mut report = |p: AnalysisProgress| {
                    let _ = ptx.send(p);
                };
                engine
                    .analyze_file_with_progress(&path, &mut report)
                    .map_err(|e| format!("{e:#}"))
            }));

            match run {
                Ok(res) => {
                    let _ = tx.send(res);
                }
                Err(panic_payload) => {
                    let msg = panic_payload
                        .downcast_ref::<&str>()
                        .map(|s| (*s).to_string())
                        .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "unknown panic payload".to_string());
                    write_error_log("analysis thread panic", &msg, Backtrace::force_capture());
                    let _ = tx.send(Err(
                        "Crash during analysis. See error.log next to the executable.".to_string(),
                    ));
                }
            }
        });
    }

    fn poll_progress(&mut self) {
        let Some(rx) = self.progress_rx.as_ref() else {
            return;
        };
        while let Ok(p) = rx.try_recv() {
            self.progress = Some(p);
        }
    }

    fn poll_analysis(&mut self) {
        let Some(rx) = self.analysis_rx.as_ref() else {
            return;
        };
        match rx.try_recv() {
            Ok(Ok(result)) => {
                self.warnings = result.warnings.clone();
                if self.warnings.iter().any(|w| {
                    w.to_lowercase()
                        .contains("re-analyze once installation is finished")
                }) {
                    self.waiting_for_tools_to_rescan = true;
                    self.processing_start_time = None;
                }

                if !result.js_files.is_empty()
                    || (!result.deobfuscated_files.is_empty()
                        && result
                            .deobfuscated_files
                            .iter()
                            .any(|(n, _)| !n.starts_with("carved_")))
                {
                    let is_python = has_python_extracted_code(&result);
                    let has_js = !result.js_files.is_empty();

                    if has_js {
                        self.code_viewer.file_selected = 0;
                        if let Some(file) = result.js_files.first() {
                            self.code_viewer.code_name = file.name.clone();
                            self.code_viewer
                                .set_content(file.original.clone().unwrap_or_default());
                        }
                    } else {
                        self.code_viewer.file_selected = result
                            .deobfuscated_files
                            .iter()
                            .position(|(n, _)| is_python && n.contains("main.pyc"))
                            .or_else(|| {
                                result
                                    .deobfuscated_files
                                    .iter()
                                    .position(|(n, _)| is_python && n.contains("__main__"))
                            })
                            .or_else(|| {
                                result
                                    .deobfuscated_files
                                    .iter()
                                    .position(|(n, _)| !is_python && n.contains("_cleaned"))
                            })
                            .unwrap_or(0);
                        if is_python
                            && result
                                .deobfuscated_files
                                .get(self.code_viewer.file_selected)
                                .is_some_and(|(n, _)| is_python_pyz_related(n))
                        {
                            self.code_viewer.file_selected = result
                                .deobfuscated_files
                                .iter()
                                .position(|(n, _)| !is_python_pyz_related(n))
                                .unwrap_or(self.code_viewer.file_selected);
                        }
                        if let Some((name, code)) = result
                            .deobfuscated_files
                            .get(self.code_viewer.file_selected)
                        {
                            self.code_viewer.code_name = name.clone();
                            self.code_viewer.set_content(code.clone());
                        }
                    }
                }
                self.last_result = Some(result);
                self.last_error = None;
                self.analysis_rx = None;
                self.progress_rx = None;
                self.running = false;
            }
            Ok(Err(err)) => {
                self.last_error = Some(err);
                self.last_result = None;
                self.analysis_rx = None;
                self.progress_rx = None;
                self.running = false;
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                self.last_error = Some("Analysis interrupted".to_string());
                self.running = false;
                self.analysis_rx = None;
                self.progress_rx = None;
            }
        }
    }
    fn poll_report_status(&mut self) {
        if let Some(rx) = &self.report_status_rx {
            match rx.try_recv() {
                Ok(msg) => {
                    self.send_report_state.status_message = Some(msg);
                    self.report_status_rx = None; // Assume one message per send for now (success or error)
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.report_status_rx = None;
                }
            }
        }
    }

    fn reset_state(&mut self) {
        self.code_viewer = CodeViewerState::default();
        if let Some(result) = &self.last_result {
            // Find extracted dir
            let mut dir_to_delete = None;
            for (_, path_str) in &result.deobfuscated_file_locations {
                let path = std::path::Path::new(path_str);
                for ancestor in path.ancestors() {
                    if let Some(name) = ancestor.file_name() {
                        let name_str = name.to_string_lossy();
                        if name_str.starts_with("singularity_extracted_") {
                            dir_to_delete = Some(ancestor.to_path_buf());
                            break;
                        }
                    }
                }
                if dir_to_delete.is_some() {
                    break;
                }
            }

            if let Some(dir) = dir_to_delete {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
        self.current_path = None;
        self.detected_type = None;
        self.detected_language = None;
        self.last_result = None;
        self.last_error = None;
        self.warnings.clear();
        self.analysis_rx = None;
        self.progress_rx = None;
    }
}

impl eframe::App for SingularityApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_progress();
        self.poll_analysis();
        self.poll_report_status();

        // Auto-rescan logic
        if self.waiting_for_tools_to_rescan {
            let status = ToolManager::global().get_status();
            if matches!(status, InstallationStatus::Finished) {
                self.waiting_for_tools_to_rescan = false;
                if let Some(path) = self.current_path.clone() {
                    self.start_analysis(path);
                }
            }
        }

        if !ctx.input(|i| i.raw.dropped_files.is_empty()) {
            let dropped = ctx.input(|i| i.raw.dropped_files.clone());
            if let Some(file) = dropped.first() {
                if let Some(path) = &file.path {
                    self.start_analysis(path.clone());
                }
            }
        }

        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Open File").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        self.start_analysis(path);
                    }
                }
                if ui.button("Clear All").clicked() {
                    self.reset_state();
                }
                if ui.button("Misc").clicked() {
                    self.show_misc_window = !self.show_misc_window;
                }
                if ui.button("Project").clicked() {
                    self.projects_state.show_window = !self.projects_state.show_window;
                    if self.projects_state.show_window {
                        self.projects_state.refresh();
                    }
                }
            });
        });

        if self.show_misc_window {
            self.misc_tools.show(ctx, &mut self.show_misc_window);
        }

        if let Some(action) = self.projects_state.show(ctx) {
            match action {
                ProjectAction::Open(path) => {
                    self.start_analysis(path);
                }
                ProjectAction::Delete(path) => {
                    let _ = std::fs::remove_dir_all(path);
                    self.projects_state.refresh();
                }
            }
        }

        egui::TopBottomPanel::bottom("bottom_panel").show(ctx, |ui| {
            ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                ui.label("Made with");
                ui.label(egui::RichText::new("\u{2764}").color(egui::Color32::from_rgb(255, 0, 0)));
                ui.label("by Sora");
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            if self.running || self.waiting_for_tools_to_rescan {
                ui.centered_and_justified(|ui| {
                    ui.vertical_centered(|ui| {
                        ui.set_max_width(300.0);

                        // Custom double circle spinner
                        let fraction = if self.waiting_for_tools_to_rescan {
                            0.5
                        } else {
                            self.progress.as_ref().map(|p| p.fraction).unwrap_or(0.0)
                        };

                        let spinner_size = 100.0;
                        let (response, painter) = ui.allocate_painter(
                            egui::Vec2::splat(spinner_size),
                            egui::Sense::hover(),
                        );

                        let center = response.rect.center();
                        let time = ui.input(|i| i.time);

                        // Helper for drawing arcs
                        let draw_arc = |radius: f32,
                                        speed: f64,
                                        stroke: egui::Stroke,
                                        reverse: bool| {
                            let points: Vec<egui::Pos2> = (0..=100)
                                .map(|i| {
                                    let t = i as f64 / 100.0;
                                    let angle = if reverse {
                                        -time * speed + t * std::f64::consts::TAU * 0.75
                                    } else {
                                        time * speed + t * std::f64::consts::TAU * 0.75
                                    };
                                    center
                                        + egui::Vec2::new(angle.cos() as f32, angle.sin() as f32)
                                            * radius
                                })
                                .collect();
                            painter.add(egui::Shape::line(points, stroke));
                        };

                        // Outer Circle
                        draw_arc(
                            spinner_size * 0.45,
                            2.0,
                            egui::Stroke::new(3.0, egui::Color32::WHITE),
                            false,
                        );

                        // Inner Circle
                        draw_arc(
                            spinner_size * 0.30,
                            3.0,
                            egui::Stroke::new(2.5, egui::Color32::from_gray(200)),
                            true,
                        );

                        // Request repaint for smooth animation
                        ui.ctx().request_repaint();

                        // Percentage Text
                        painter.text(
                            center,
                            egui::Align2::CENTER_CENTER,
                            format!("{:.0}%", fraction * 100.0),
                            egui::FontId::proportional(20.0),
                            egui::Color32::WHITE,
                        );

                        ui.add_space(20.0);

                        // Detailed Step Text
                        let status_text = if self.waiting_for_tools_to_rescan {
                            "Installing dependencies...".to_string()
                        } else if let Some(p) = &self.progress {
                            p.step.clone()
                        } else {
                            "Initializing analysis environment...".to_string()
                        };

                        ui.label(
                            egui::RichText::new(status_text)
                                .size(18.0)
                                .strong()
                                .color(egui::Color32::WHITE),
                        );

                        if let Some(start) = self.processing_start_time {
                            if start.elapsed().as_secs() > 15 {
                                ui.add_space(8.0);
                                ui.label(
                                    egui::RichText::new(
                                        "Analysis is detailed and may take a moment...",
                                    )
                                    .size(12.0)
                                    .color(egui::Color32::from_gray(180)),
                                );
                            }
                        }
                    });
                });
            } else if let Some(err) = &self.last_error {
                ui.colored_label(egui::Color32::RED, format!("Error: {err}"));
            } else if let Some(result) = &self.last_result {
                self.tabs.show(
                    ui,
                    result,
                    &mut self.string_search_query,
                    &mut self.disassembly_search_query,
                    &mut self.code_viewer,
                    &mut self.send_report_state,
                    &mut self.report_status_rx,
                    &mut self.online_scanner,
                    &mut self.js_sandbox_ui,
                );
            } else {
                ui.centered_and_justified(|ui| {
                    ui.label("Drag and drop a file to analyze");
                });
            }
        });

        // Show installation progress window
        let status = ToolManager::global().get_status();
        match status {
            InstallationStatus::InstallingNode(msg)
            | InstallationStatus::InstallingPyArmor(msg)
            | InstallationStatus::InstallingSynchrony(msg) => {
                egui::Window::new("Installing Tools")
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                    .show(ctx, |ui| {
                        ui.set_min_width(200.0);
                        ui.vertical_centered(|ui| {
                            ui.label(msg);
                            ui.add_space(10.0);
                            ui.spinner();
                        });
                    });
            }
            _ => {}
        }

        // Show YARA consent dialog if needed
        if self.yara_consent.is_none() {
            egui::Window::new("YARA Rules Setup")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.heading("Install YARA Rules?");
                    ui.add_space(10.0);
                    ui.label("Singularity uses YARA rules for advanced malware detection.");
                    ui.label("Downloading the full ruleset (approx. 15MB) is recommended.");
                    ui.add_space(10.0);
                    ui.colored_label(egui::Color32::YELLOW, "⚠ Warning: Anti-Virus software may detect the .yar rules file as malicious.");
                    ui.label("This is a known false positive because the file contains malware signatures.");
                    ui.add_space(20.0);

                    ui.horizontal(|ui| {
                        if ui.button("Yes, Install Rules").clicked() {
                            self.yara_consent = Some(true);
                            let mut config = AppConfig::default();
                            config.yara_consent = Some(true);
                            config.save();

                            // Trigger start
                            self.start_background_tasks();
                        }

                        if ui.button("No, Skip").clicked() {
                            self.yara_consent = Some(false);
                            let mut config = AppConfig::default();
                            config.yara_consent = Some(false);
                            config.save();
                        }
                    });
                });
        }
    }
}

impl Tabs {
    fn show(
        &mut self,
        ui: &mut egui::Ui,
        result: &AnalysisResult,
        search_query: &mut String,
        asm_search: &mut String,
        code_viewer: &mut CodeViewerState,
        send_report_state: &mut SendReportState,
        report_status_rx: &mut Option<mpsc::Receiver<String>>,
        online_scanner: &mut OnlineScanner,
        js_sandbox_ui: &mut JsSandboxUi,
    ) {
        let is_electron = result.js_container.as_deref() == Some("electron");

        ui.horizontal(|ui| {
            let mut labels = vec![
                "Info",
                "URLs",
                "Imports",
                "Sections",
                "Strings",
                "Disassembly",
                "Secrets",
                "Extracted",
                "Layered Analysis",
                "Send Report",
                "Online Scan",
            ];

            if is_electron {
                labels.push("JS Sandbox");
            }

            for (idx, label) in labels.iter().enumerate() {
                if ui.selectable_label(self.selected == idx, *label).clicked() {
                    self.selected = idx;
                }
            }
        });
        ui.separator();

        match self.selected {
            0 => show_infos(ui, result),
            1 => show_urls(ui, result),
            2 => show_imports(ui, result),
            3 => show_sections(ui, result),
            4 => show_strings(ui, result, search_query),
            5 => show_disassembly(ui, result, asm_search),
            6 => show_secrets(ui, result),
            7 => show_extracted_code(ui, result, code_viewer, js_sandbox_ui, &mut self.selected),
            8 => show_layered_analysis(ui, result),
            9 => show_send_report(ui, result, send_report_state, report_status_rx),
            10 => {
                let ctx = ui.ctx().clone();
                online_scanner.show(&ctx, ui);
            }
            11 if is_electron => {
                let ctx = ui.ctx().clone();
                js_sandbox_ui.show(&ctx, ui);
            }
            _ => show_infos(ui, result),
        }
    }
}

fn show_layered_analysis(ui: &mut egui::Ui, result: &AnalysisResult) {
    if let Some(report) = &result.layered_report {
        ui.heading("Layered Analysis Report");
        ui.label(format!("File: {}", report.file_path));
        ui.label(format!("Final Payload Type: {}", report.final_payload_type));
        ui.separator();

        // Collect and dedup all extracted files
        let mut all_extracted_files = std::collections::BTreeSet::new();
        for layer in &report.layers {
            for file in &layer.extracted_files {
                all_extracted_files.insert(file);
            }
        }

        if !all_extracted_files.is_empty() {
            ui.label("Extracted Files:");

            let id = ui.make_persistent_id("layered_analysis_files_expanded");
            let mut expanded = ui.data(|d| d.get_temp::<bool>(id).unwrap_or(false));

            let file_list: Vec<_> = all_extracted_files.iter().collect();
            let count = file_list.len();
            let to_show = if expanded { count } else { count.min(3) };

            egui::ScrollArea::vertical()
                .max_height(150.0)
                .id_source("extracted_files_scroll")
                .show(ui, |ui| {
                    for i in 0..to_show {
                        ui.monospace(*file_list[i]);
                    }
                });

            if count > 3 {
                if ui
                    .button(if expanded { "Show Less" } else { "Show More" })
                    .clicked()
                {
                    expanded = !expanded;
                    ui.data_mut(|d| d.insert_temp(id, expanded));
                }
            }

            ui.separator();
        }

        if report.layers.is_empty() {
            ui.label("No layers detected.");
        } else {
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (i, layer) in report.layers.iter().enumerate() {
                    ui.group(|ui| {
                        ui.heading(format!("Layer {}: {:?}", i + 1, layer.layer_type));
                        ui.label(format!("Method: {}", layer.method));
                        ui.label(format!("Confidence: {}%", layer.confidence));
                        ui.label(format!("Details: {}", layer.details));

                        if !layer.guide.is_empty() {
                            ui.colored_label(egui::Color32::LIGHT_BLUE, "Interactive Guide:");
                            ui.label(&layer.guide);
                        }
                    });
                    ui.add_space(10.0);
                }
            });
        }
    } else {
        ui.label("No Layered Analysis Report available.");
    }
}

fn show_extracted_code(
    ui: &mut egui::Ui,
    result: &AnalysisResult,
    state: &mut CodeViewerState,
    js_sandbox_ui: &mut JsSandboxUi,
    selected_tab: &mut usize,
) {
    egui::SidePanel::left("code_file_list_panel_inner")
        .resizable(true)
        .default_width(220.0)
        .show_inside(ui, |ui| {
            ui.heading("Files");
            if ui.button("Reveal in folder").clicked() {
                if let Some(extracted_dir) = &result.extracted_dir {
                    let _ = std::process::Command::new("explorer")
                        .arg(extracted_dir)
                        .spawn();
                } else {
                    let tools_mgr = ToolManager::global();
                    let extracted_root = tools_mgr.get_extracted_dir();
                    let _ = std::process::Command::new("explorer")
                        .arg(extracted_root)
                        .spawn();
                }
            }

            if ui.button("🔐 Link Decryptor").clicked() {
                state.show_manual_decryptor = true;
            }

            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| {
                if !result.js_files.is_empty() {
                    for (idx, file) in result.js_files.iter().enumerate() {
                        if ui
                            .selectable_label(state.file_selected == idx, &file.name)
                            .clicked()
                        {
                            state.file_selected = idx;
                            let content = match state.view_mode.unwrap_or(ViewMode::Original) {
                                ViewMode::Original => file.original.clone().unwrap_or_default(),
                                ViewMode::Deobfuscated => file
                                    .synchrony
                                    .clone()
                                    .unwrap_or_else(|| file.original.clone().unwrap_or_default()),
                            };
                            state.code_name = file.name.clone();
                            state.set_content(content);
                        }
                    }
                } else {
                    // Categorize files
                    let mut main_files = Vec::new();
                    let mut pyz_files = Vec::new();
                    let mut pyarmor_files = Vec::new();
                    let mut lzma_zlib_files = Vec::new();
                    let mut decrypted_files = Vec::new();
                    let mut extracted_exe_files = Vec::new();
                    let mut stealer_files = Vec::new();
                    let mut stub_source_files = Vec::new();

                    for (idx, (name, _)) in result.deobfuscated_files.iter().enumerate() {
                        let location = result
                            .deobfuscated_file_locations
                            .get(idx)
                            .map(|(_, l)| l.as_str())
                            .unwrap_or("");
                        if location.contains("_pyarmor_dump") {
                            pyarmor_files.push(idx);
                        } else if name.starts_with("LZMA_ZLIB/") {
                            lzma_zlib_files.push(idx);
                        } else if name.starts_with("Extracted Exe/") {
                            extracted_exe_files.push(idx);
                        } else if name.starts_with("Decrypted/") {
                            decrypted_files.push(idx);
                        } else if name.starts_with("Stealer/") {
                            stealer_files.push(idx);
                        } else if name.starts_with("Stub Source/") {
                            stub_source_files.push(idx);
                        } else if is_python_pyz_related(name) {
                            pyz_files.push(idx);
                        } else {
                            main_files.push(idx);
                        }
                    }

                    let mut draw_file = |ui: &mut egui::Ui, idx: usize, name: &str| {
                        if ui
                            .selectable_label(state.file_selected == idx, name)
                            .clicked()
                        {
                            state.file_selected = idx;
                            state.code_name = name.to_string();
                            if let Some((_, content)) = result.deobfuscated_files.get(idx) {
                                state.set_content(content.clone());
                            }
                        }
                    };

                    ui.collapsing("Main Files", |ui| {
                        for &idx in &main_files {
                            if let Some((name, _)) = result.deobfuscated_files.get(idx) {
                                draw_file(ui, idx, name);
                            }
                        }
                    });

                    if !stub_source_files.is_empty() {
                        ui.collapsing("Stub Source", |ui| {
                            for &idx in &stub_source_files {
                                if let Some((name, _)) = result.deobfuscated_files.get(idx) {
                                    let display_name =
                                        name.strip_prefix("Stub Source/").unwrap_or(name);
                                    draw_file(ui, idx, display_name);
                                }
                            }
                        });
                    }

                    if !extracted_exe_files.is_empty() {
                        ui.collapsing("Extracted Exe", |ui| {
                            for &idx in &extracted_exe_files {
                                if let Some((name, _)) = result.deobfuscated_files.get(idx) {
                                    let display_name =
                                        name.strip_prefix("Extracted Exe/").unwrap_or(name);
                                    draw_file(ui, idx, display_name);
                                }
                            }
                        });
                    }

                    if !decrypted_files.is_empty() {
                        ui.collapsing("Decrypted", |ui| {
                            for &idx in &decrypted_files {
                                if let Some((name, _)) = result.deobfuscated_files.get(idx) {
                                    let display_name =
                                        name.strip_prefix("Decrypted/").unwrap_or(name);
                                    draw_file(ui, idx, display_name);
                                }
                            }
                        });
                    }

                    if !stealer_files.is_empty() {
                        ui.collapsing("Stealer", |ui| {
                            for &idx in &stealer_files {
                                if let Some((name, _)) = result.deobfuscated_files.get(idx) {
                                    let display_name =
                                        name.strip_prefix("Stealer/").unwrap_or(name);
                                    draw_file(ui, idx, display_name);
                                }
                            }
                        });
                    }

                    if !lzma_zlib_files.is_empty() {
                        ui.collapsing("LZMA / ZLIB Deobfuscated", |ui| {
                            for &idx in &lzma_zlib_files {
                                if let Some((name, _)) = result.deobfuscated_files.get(idx) {
                                    // Strip prefix for cleaner display
                                    let display_name =
                                        name.strip_prefix("LZMA_ZLIB/").unwrap_or(name);
                                    draw_file(ui, idx, display_name);
                                }
                            }
                        });
                    }

                    if !pyz_files.is_empty() {
                        ui.collapsing("PYZ Files", |ui| {
                            for &idx in &pyz_files {
                                if let Some((name, _)) = result.deobfuscated_files.get(idx) {
                                    draw_file(ui, idx, name);
                                }
                            }
                        });
                    }

                    if !pyarmor_files.is_empty() {
                        ui.collapsing("PyArmor Deobfuscated", |ui| {
                            for &idx in &pyarmor_files {
                                if let Some((name, _)) = result.deobfuscated_files.get(idx) {
                                    draw_file(ui, idx, name);
                                }
                            }
                        });
                    }
                }
            });
        });

    egui::CentralPanel::default().show_inside(ui, |ui| {
        ui.horizontal(|ui| {
            // Only show view mode buttons for JS files where we have both versions for the same file entry
            // For Python/PyArmor, we have separate files in the file tree, so no mode switch needed
            let show_buttons = !result.js_files.is_empty();

            if show_buttons {
                if ui
                    .selectable_label(state.view_mode == Some(ViewMode::Original), "Original")
                    .clicked()
                {
                    state.view_mode = Some(ViewMode::Original);
                    // Re-trigger selection logic
                    if !result.js_files.is_empty() {
                        if let Some(file) = result.js_files.get(state.file_selected) {
                            let content = file.original.clone().unwrap_or_default();
                            state.set_content(content);
                        }
                    }
                }
                if ui
                    .selectable_label(
                        state.view_mode == Some(ViewMode::Deobfuscated),
                        "Deobfuscated",
                    )
                    .clicked()
                {
                    state.view_mode = Some(ViewMode::Deobfuscated);
                    if !result.js_files.is_empty() {
                        if let Some(file) = result.js_files.get(state.file_selected) {
                            let content = file
                                .synchrony
                                .clone()
                                .unwrap_or_else(|| file.original.clone().unwrap_or_default());
                            state.set_content(content);
                        }
                    }
                }
            } else {
                // Force Original view mode if buttons are hidden (just to be safe)
                // But only if we are not already in some state
            }

            ui.separator();
            ui.label("Search:");
            ui.text_edit_singleline(&mut state.search_query);

            ui.separator();
            let is_electron = result.js_container.as_deref() == Some("electron");
            if is_electron && state.view_mode != Some(ViewMode::Deobfuscated) {
                if ui.button("🛡 Simulate in Sandbox").clicked() {
                    js_sandbox_ui.set_code(state.code_cache.clone());
                    *selected_tab = 10; // Switch to JS Sandbox tab
                }
            }
        });
        ui.separator();

        egui::ScrollArea::vertical()
            .id_source("code_viewer_scroll_area")
            .auto_shrink([false, false]) // Let ScrollArea fill the space
            .show(ui, |ui| {
                if state.search_query.is_empty() {
                    ui.add(
                        egui::TextEdit::multiline(&mut state.code_cache)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY)
                            .code_editor(),
                    );
                } else {
                    if state.search_query != state.last_search_query {
                        let query = state.search_query.to_lowercase();
                        state.cached_search_result = state
                            .full_content
                            .lines()
                            .filter(|l| l.to_lowercase().contains(&query))
                            .collect::<Vec<_>>()
                            .join("\n");
                        state.last_search_query = state.search_query.clone();
                    }

                    ui.label(
                        egui::RichText::new(format!(
                            "Searching in full content ({} KB)...",
                            state.full_content.len() / 1024
                        ))
                        .italics(),
                    );

                    ui.add(
                        egui::TextEdit::multiline(&mut state.cached_search_result)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY)
                            .code_editor(),
                    );
                }

                if state.loaded_limit < state.full_content.len() {
                    ui.add_space(10.0);
                    ui.separator();
                    let remaining = state.full_content.len() - state.loaded_limit;
                    let btn_text =
                        format!("Load Next Chunk ({} KB remaining)...", remaining / 1024);

                    // Infinite scroll: load when button becomes visible
                    let btn =
                        ui.add_sized([ui.available_width(), 30.0], egui::Button::new(btn_text));
                    if btn.clicked() || (btn.rect.min.y < ui.clip_rect().max.y) {
                        state.load_more();
                    }
                }
            });
    });

    if state.show_manual_decryptor {
        egui::Window::new("🔐 Manual Link Decryptor")
            .open(&mut state.show_manual_decryptor)
            .resizable(true)
            .default_width(600.0)
            .default_height(400.0)
            .show(ui.ctx(), |ui| {
                ui.label("Enter Encrypted Link / Ciphertext (Base64/Hex/Raw):");
                ui.add(egui::TextEdit::multiline(&mut state.manual_input_link).desired_rows(3));

                ui.separator();

                ui.label("Enter Key / Password (Base64/Hex/Raw):");
                ui.text_edit_singleline(&mut state.manual_input_key);

                ui.separator();

                if ui.button("Decrypt").clicked() {
                    state.manual_output = crate::link_decryptor::manual_decrypt(
                        &state.manual_input_link,
                        &state.manual_input_key,
                    );
                }

                ui.separator();
                ui.heading("Output:");
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut state.manual_output)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY),
                    );
                });
            });
    }
}

fn show_infos(ui: &mut egui::Ui, result: &AnalysisResult) {
    if let Some(name) = result.file_path.file_name().and_then(|n| n.to_str()) {
        ui.label(format!("File: {}", name));
    }
    ui.label(format!("Path: {}", result.file_path.display()));
    ui.label(format!("Type: {}", result.file_format));
    ui.label(format!("Language: {}", result.language));
    ui.label(format!("Kind: {}", result.kind));
    ui.label(format!("Size: {} bytes", result.file_size));
    if let Some(ep) = result.entry_point {
        ui.label(format!("Entry: 0x{ep:016x}"));
    }
    if let Some(ep) = &result.python_entrypoint {
        ui.label(format!("Python entrypoint: {ep}"));
    }
    if let Some(c) = &result.js_container {
        ui.label(format!("JS container: {c}"));
    }
    if !result.js_files.is_empty() || result.js_obfuscated || result.language == "JavaScript" {
        ui.label(format!(
            "JS obfuscated: {}",
            if result.js_obfuscated { "Yes" } else { "No" }
        ));
    }
    if result.is_stealer {
        ui.add(egui::Label::new(
            egui::RichText::new(" Stealer ")
                .color(egui::Color32::BLACK)
                .background_color(egui::Color32::WHITE)
                .strong(),
        ));
    }
    ui.separator();
    if result.yara_matches.is_empty() {
        ui.label("YARA Matches: None");
    } else {
        ui.colored_label(egui::Color32::RED, "YARA Matches:");
        for m in &result.yara_matches {
            ui.colored_label(egui::Color32::LIGHT_RED, m);
        }
    }
    if !result.warnings.is_empty() {
        ui.separator();
        ui.colored_label(egui::Color32::YELLOW, "Warnings:");
        for w in &result.warnings {
            ui.label(w);
        }
    }
}

fn show_urls(ui: &mut egui::Ui, result: &AnalysisResult) {
    let urls = extract_urls(result);
    if urls.is_empty() {
        ui.label("No URLs found.");
        return;
    }
    egui::ScrollArea::vertical().show(ui, |ui| {
        for u in urls {
            ui.monospace(u);
        }
    });
}

fn show_imports(ui: &mut egui::Ui, result: &AnalysisResult) {
    if result.imports.is_empty() {
        ui.label("No imports found.");
        return;
    }
    egui::ScrollArea::vertical().show(ui, |ui| {
        for imp in &result.imports {
            ui.monospace(imp);
        }
    });
}

fn detect_basic(path: &Path) -> (String, String) {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    if ext == "pyc" {
        return (".pyc".to_string(), "Python".to_string());
    }

    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return ("Unknown".to_string(), "Unknown".to_string()),
    };

    let mut head = vec![0u8; 64 * 1024];
    let head_n = f.read(&mut head).unwrap_or(0);
    head.truncate(head_n);

    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let mut tail = Vec::new();
    if len > 0 {
        let tail_len = (64 * 1024u64).min(len);
        if f.seek(SeekFrom::End(-(tail_len as i64))).is_ok() {
            tail.resize(tail_len as usize, 0);
            let tail_n = f.read(&mut tail).unwrap_or(0);
            tail.truncate(tail_n);
        }
    }

    const MEI_MAGIC: &[u8] = b"MEI\x0c\x0b\x0a\x0b\x0e";
    let is_pyinstaller = head.windows(MEI_MAGIC.len()).any(|w| w == MEI_MAGIC)
        || tail.windows(MEI_MAGIC.len()).any(|w| w == MEI_MAGIC);
    if is_pyinstaller {
        return ("PyInstaller executable".to_string(), "Python".to_string());
    }

    if head.starts_with(b"MZ") {
        return ("PE".to_string(), "Native".to_string());
    }
    if head.starts_with(b"\x7fELF") {
        return ("ELF".to_string(), "Native".to_string());
    }
    if head.len() >= 4 {
        let magic = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
        let magic_le = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
        let is_macho = matches!(magic, 0xfeedface | 0xfeedfacf | 0xcafebabe | 0xcafebabf)
            || matches!(magic_le, 0xfeedface | 0xfeedfacf | 0xcafebabe | 0xcafebabf);
        if is_macho {
            return ("Mach-O".to_string(), "Native".to_string());
        }
    }

    ("Unknown".to_string(), "Unknown".to_string())
}

pub fn write_error_log(context: &str, message: &str, backtrace: Backtrace) -> Option<PathBuf> {
    let path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("error.log")))
        .unwrap_or_else(|| std::env::temp_dir().join("error.log"));

    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = writeln!(f, "=== {ts} | {context} ===");
        let _ = writeln!(f, "{message}");
        let _ = writeln!(f, "{backtrace}");
        let _ = writeln!(f);
        Some(path)
    } else {
        None
    }
}

fn show_sections(ui: &mut egui::Ui, result: &AnalysisResult) {
    egui::ScrollArea::vertical().show(ui, |ui| {
        egui::Grid::new("sections_grid")
            .striped(true)
            .show(ui, |ui| {
                ui.label("Name");
                ui.label("VA");
                ui.label("VSize");
                ui.label("Offset");
                ui.label("FSize");
                ui.end_row();

                for s in &result.sections {
                    ui.label(&s.name);
                    ui.label(
                        s.virtual_address
                            .map(|v| format!("0x{v:016x}"))
                            .unwrap_or("-".to_string()),
                    );
                    ui.label(
                        s.virtual_size
                            .map(|v| format!("0x{v:x}"))
                            .unwrap_or("-".to_string()),
                    );
                    ui.label(
                        s.file_offset
                            .map(|v| format!("0x{v:x}"))
                            .unwrap_or("-".to_string()),
                    );
                    ui.label(
                        s.file_size
                            .map(|v| format!("0x{v:x}"))
                            .unwrap_or("-".to_string()),
                    );
                    ui.end_row();
                }
            });
    });
}

fn show_strings(ui: &mut egui::Ui, result: &AnalysisResult, search_query: &mut String) {
    ui.horizontal(|ui| {
        ui.label("Search:");
        ui.text_edit_singleline(search_query);
        if ui.button("Clear").clicked() {
            search_query.clear();
        }
    });
    ui.separator();

    let available_height = ui.available_height();
    egui::ScrollArea::vertical()
        .max_height(available_height)
        .show(ui, |ui| {
            let query = search_query.to_lowercase();
            for s in &result.strings {
                if query.is_empty() || s.to_lowercase().contains(&query) {
                    ui.monospace(s);
                }
            }
        });
}

fn show_disassembly(ui: &mut egui::Ui, result: &AnalysisResult, search_query: &mut String) {
    ui.horizontal(|ui| {
        ui.label("Search:");
        ui.text_edit_singleline(search_query);
        if ui.button("Clear").clicked() {
            search_query.clear();
        }
    });
    ui.separator();

    let mut text = if result.disassembly.is_empty() {
        let maybe_python = result.external.iter().find(|o| {
            o.tool.contains("disassemble")
                || o.tool.contains("python-dis")
                || o.tool.contains("python_dis")
        });
        maybe_python
            .map(|o| o.stdout.clone())
            .unwrap_or_else(|| "No disassembly available.".to_string())
    } else {
        let query = search_query.to_lowercase();
        result
            .disassembly
            .iter()
            .filter(|l| {
                if query.is_empty() {
                    true
                } else {
                    l.op_str.to_lowercase().contains(&query)
                        || l.mnemonic.to_lowercase().contains(&query)
                        || format!("{:x}", l.address).contains(&query)
                }
            })
            .map(|l| {
                format!(
                    "0x{:016x}: {:<24} {:<8} {}",
                    l.address, l.bytes_hex, l.mnemonic, l.op_str
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    if !result.disassembly.is_empty() && text.is_empty() && !search_query.is_empty() {
        text = "No matches found.".to_string();
    } else if result.disassembly.is_empty() && !search_query.is_empty() {
        // Filter external tool output line by line
        let query = search_query.to_lowercase();
        text = text
            .lines()
            .filter(|line| line.to_lowercase().contains(&query))
            .collect::<Vec<_>>()
            .join("\n");
        if text.is_empty() {
            text = "No matches found.".to_string();
        }
    }

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.add(
                egui::TextEdit::multiline(&mut text)
                    .font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY)
                    .code_editor(),
            );
        });
}

// External section removed

fn show_secrets(ui: &mut egui::Ui, result: &AnalysisResult) {
    if result.secrets.is_empty() {
        ui.label("No secrets detected.");
        return;
    }
    egui::ScrollArea::vertical().show(ui, |ui| {
        for secret in &result.secrets {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.colored_label(egui::Color32::RED, &secret.kind);
                    ui.label(":");
                    ui.monospace(&secret.value);
                });
                ui.label(format!("Context: {}", secret.context));
            });
        }
    });
}

pub fn configure_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();

    // Background colors - Almost Black
    visuals.window_fill = egui::Color32::from_rgb(5, 5, 5);
    visuals.panel_fill = egui::Color32::from_rgb(5, 5, 5);

    // Widgets
    visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(5, 5, 5);
    visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, egui::Color32::WHITE);

    // Buttons (inactive) - Very Dark Gray
    visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(20, 20, 20);
    visuals.widgets.inactive.rounding = egui::Rounding::same(4.0);
    visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, egui::Color32::WHITE);

    // Buttons (hovered) - Dark Gray
    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(40, 40, 40);
    visuals.widgets.hovered.rounding = egui::Rounding::same(4.0);
    visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, egui::Color32::WHITE);

    // Buttons (active/clicked) - White background, dark text
    visuals.widgets.active.bg_fill = egui::Color32::WHITE;
    visuals.widgets.active.rounding = egui::Rounding::same(4.0);
    visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, egui::Color32::BLACK);

    // Selection
    visuals.selection.bg_fill = egui::Color32::from_rgb(50, 50, 50);
    visuals.selection.stroke = egui::Stroke::new(1.0, egui::Color32::WHITE);

    ctx.set_visuals(visuals);

    // Style adjustments
    let mut style = (*ctx.style()).clone();
    style.spacing.button_padding = egui::vec2(16.0, 10.0); // More spacing for modern look
    style.spacing.item_spacing = egui::vec2(12.0, 12.0);
    style.spacing.scroll.bar_width = 12.0;
    style.spacing.scroll.handle_min_length = 24.0;

    // Font setup for a cleaner look (optional, but good for "modern")
    // We stick to default fonts but maybe increase size slightly if needed?
    // keeping default for now to avoid complexity with font loading.

    ctx.set_style(style);
}

fn show_send_report(
    ui: &mut egui::Ui,
    result: &AnalysisResult,
    state: &mut SendReportState,
    report_status_rx: &mut Option<mpsc::Receiver<String>>,
) {
    ui.heading("Send Analysis Report");
    ui.add_space(10.0);

    egui::ScrollArea::vertical().show(ui, |ui| {
        egui::Grid::new("send_report_grid")
            .num_columns(2)
            .spacing([10.0, 10.0])
            .show(ui, |ui| {
                ui.label("Webhook URL:");
                ui.text_edit_singleline(&mut state.webhook_url);
                ui.end_row();

                ui.label("Message:");
                ui.add(
                    egui::TextEdit::multiline(&mut state.message)
                        .desired_width(400.0)
                        .desired_rows(5),
                );
                ui.end_row();

                ui.label("Options:");
                ui.horizontal(|ui| {
                    ui.checkbox(
                        &mut state.include_embeds,
                        "Include Embeds (Analysis Summary)",
                    );
                });
                ui.end_row();

                ui.label("Custom Embed JSON:");
                egui::ScrollArea::vertical()
                    .id_source("custom_embed_json_scroll")
                    .max_height(150.0)
                    .show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut state.custom_embed_json)
                                .desired_width(400.0)
                                .code_editor(),
                        );
                    });
                ui.end_row();

                ui.label("Image:");
                ui.horizontal(|ui| {
                    if let Some(path) = &state.image_path {
                        ui.label(path.file_name().unwrap_or_default().to_string_lossy());
                        if ui.button("Clear").clicked() {
                            state.image_path = None;
                        }
                    } else {
                        ui.label("No image selected");
                    }
                    if ui.button("Select Image").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("Images", &["png", "jpg", "jpeg", "gif", "bmp"])
                            .pick_file()
                        {
                            state.image_path = Some(path);
                        }
                    }
                });
                ui.end_row();
            });

        ui.add_space(20.0);

        if ui.button("Send Report").clicked() {
            if state.webhook_url.trim().is_empty() {
                state.status_message = Some("Please enter a Webhook URL.".to_string());
            } else {
                // Validate JSON if provided
                let custom_embed_val = if !state.custom_embed_json.trim().is_empty() {
                    match serde_json::from_str::<serde_json::Value>(&state.custom_embed_json) {
                        Ok(val) => Some(val),
                        Err(e) => {
                            state.status_message =
                                Some(format!("Invalid Custom Embed JSON: {}", e));
                            return;
                        }
                    }
                } else {
                    None
                };

                state.status_message = Some("Sending report...".to_string());
                let webhook_url = state.webhook_url.clone();
                let message = state.message.clone();
                let include_embeds = state.include_embeds;
                let image_path = state.image_path.clone();

                // Prepare summary for embeds
                let summary = if include_embeds {
                    Some(format!(
                        "**Analysis Report**\nFile: {}\nType: {}\nScore: {}/10\nSecrets: {}",
                        result
                            .file_path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy(),
                        result.kind,
                        result.confidence_score,
                        result.secrets.len()
                    ))
                } else {
                    None
                };

                let (tx, rx) = mpsc::channel();
                *report_status_rx = Some(rx);

                std::thread::spawn(move || {
                    let client = reqwest::blocking::Client::new();

                    // Construct payload_json
                    // If payload_json is used, 'content' must be inside it.
                    // We will collect all embeds into a list.

                    let mut embeds = Vec::new();

                    if let Some(summary) = summary {
                        embeds.push(json!({
                            "title": "Singularity Analysis Result",
                            "description": summary,
                            "color": 16711680 // Red-ish
                        }));
                    }

                    if let Some(custom) = custom_embed_val {
                        if let Some(arr) = custom.as_array() {
                            for item in arr {
                                if item.is_object() {
                                    embeds.push(item.clone());
                                }
                            }
                        } else if let Some(obj) = custom.as_object() {
                            // Check if the user pasted a full payload object containing "embeds" array
                            if let Some(inner_embeds) = obj.get("embeds").and_then(|v| v.as_array())
                            {
                                for item in inner_embeds {
                                    if item.is_object() {
                                        embeds.push(item.clone());
                                    }
                                }
                            } else {
                                // Assume the object itself is the embed
                                embeds.push(custom);
                            }
                        }
                    }

                    let mut payload_obj = serde_json::Map::new();

                    if !message.is_empty() {
                        payload_obj.insert("content".to_string(), json!(message));
                    }

                    if !embeds.is_empty() {
                        payload_obj.insert("embeds".to_string(), json!(embeds));
                    }

                    let res = if let Some(path) = image_path {
                        // Multipart mode
                        let mut multipart = reqwest::blocking::multipart::Form::new();

                        if !payload_obj.is_empty() {
                            multipart = multipart.text(
                                "payload_json",
                                serde_json::Value::Object(payload_obj.clone()).to_string(),
                            );
                        }

                        if let Ok(file_name) = path
                            .file_name()
                            .ok_or("Invalid path")
                            .map(|n| n.to_string_lossy().to_string())
                        {
                            if let Ok(bytes) = std::fs::read(&path) {
                                let part = reqwest::blocking::multipart::Part::bytes(bytes)
                                    .file_name(file_name);
                                multipart = multipart.part("file", part);
                            }
                        }

                        client.post(&webhook_url).multipart(multipart).send()
                    } else {
                        // JSON mode
                        client
                            .post(&webhook_url)
                            .json(&serde_json::Value::Object(payload_obj))
                            .send()
                    };

                    match res {
                        Ok(resp) => {
                            if resp.status().is_success() {
                                let _ = tx.send("Report sent successfully!".to_string());
                            } else {
                                let status = resp.status();
                                let text = resp
                                    .text()
                                    .unwrap_or_else(|_| "No response body".to_string());
                                let _ = tx.send(format!("Failed to send: {} - {}", status, text));
                            }
                        }
                        Err(e) => {
                            let _ = tx.send(format!("Error: {}", e));
                        }
                    }
                });
            }
        }

        if let Some(status) = &state.status_message {
            ui.add_space(10.0);
            ui.label(status);
        }

        ui.add_space(20.0);
        ui.separator();
        ui.heading("Delete Webhook");
        ui.label("Enter the Webhook URL above to delete it.");
        if ui.button("Delete Webhook").clicked() {
            if state.webhook_url.trim().is_empty() {
                state.status_message = Some("Please enter a Webhook URL to delete.".to_string());
            } else {
                state.status_message = Some("Deleting webhook...".to_string());
                let webhook_url = state.webhook_url.clone();
                let (tx, rx) = mpsc::channel();
                *report_status_rx = Some(rx);

                std::thread::spawn(move || {
                    let client = reqwest::blocking::Client::new();
                    match client.delete(&webhook_url).send() {
                        Ok(resp) => {
                            if resp.status().is_success()
                                || resp.status() == reqwest::StatusCode::NO_CONTENT
                            {
                                let _ = tx.send("Webhook deleted successfully!".to_string());
                            } else {
                                let _ = tx.send(format!("Failed to delete: {}", resp.status()));
                            }
                        }
                        Err(e) => {
                            let _ = tx.send(format!("Error: {}", e));
                        }
                    }
                });
            }
        }
    });
}
