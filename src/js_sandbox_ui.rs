use crate::js_sandbox::JsSandbox;
use eframe::egui;
use std::io::Write;
use std::path::Path;

pub struct JsSandboxUi {
    pub code: String,
    pub logs: Vec<String>,
    sandbox: JsSandbox,
}

impl Default for JsSandboxUi {
    fn default() -> Self {
        Self {
            code: String::new(),
            logs: Vec::new(),
            sandbox: JsSandbox::new(),
        }
    }
}

impl JsSandboxUi {
    pub fn set_code(&mut self, code: String) {
        self.code = code;
    }

    pub fn show(&mut self, _ctx: &egui::Context, ui: &mut egui::Ui) {
        ui.heading("JavaScript Malware Sandbox");
        ui.label("Safe execution environment mocking 'fs', 'child_process', and 'http'.");
        ui.label("This sandbox runs isolated from your system.");

        ui.add_space(5.0);

        ui.horizontal(|ui| {
            if ui.button("▶ Run Simulation").clicked() {
                self.logs.clear();
                self.logs.push("--- Starting Simulation ---".to_string());
                // Re-create sandbox to clear state
                self.sandbox = JsSandbox::new();
                let new_logs = self.sandbox.run_script(&self.code);
                self.logs.extend(new_logs);
                self.logs.push("--- Simulation Ended ---".to_string());

                // Check for decrypted payload and auto-run
                if Path::new("decrypted_payload.js").exists() {
                    if let Ok(payload) = std::fs::read_to_string("decrypted_payload.js") {
                        self.logs.push(
                            "\n--- Detected Decrypted Payload - Starting Second Pass ---"
                                .to_string(),
                        );

                        // Create a fresh sandbox for the payload to avoid context pollution
                        self.sandbox = JsSandbox::new();
                        let payload_logs = self.sandbox.run_script(&payload);
                        self.logs.extend(payload_logs);

                        self.logs.push("--- Second Pass Ended ---".to_string());

                        // Cleanup (optional, but good for testing)
                        let _ = std::fs::remove_file("decrypted_payload.js");
                    }
                }
            }
            if ui.button("Clear Logs").clicked() {
                self.logs.clear();
            }
            if ui.button("Clear Code").clicked() {
                self.code.clear();
            }

            ui.separator();

            if ui.button("📋 Copy Traces").clicked() {
                let content = self.logs.join("\n");
                ui.output_mut(|o| o.copied_text = content);
            }

            if ui.button("💾 Export to .txt").clicked() {
                let content = self.logs.join("\n");
                if let Some(path) = rfd::FileDialog::new()
                    .set_file_name("trace.txt")
                    .save_file()
                {
                    if let Ok(mut file) = std::fs::File::create(path) {
                        let _ = file.write_all(content.as_bytes());
                    }
                }
            }
        });

        ui.separator();

        // Split view: Code on left, Logs on right
        egui::SidePanel::right("sandbox_logs")
            .resizable(true)
            .default_width(400.0)
            .show_inside(ui, |ui| {
                ui.heading("Execution Traces");
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for log in &self.logs {
                        ui.label(egui::RichText::new(log).monospace());
                    }
                });
            });

        egui::CentralPanel::default().show_inside(ui, |ui| {
            ui.heading("Malware Source Code");
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut self.code)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY)
                        .code_editor(),
                );
            });
        });
    }
}
