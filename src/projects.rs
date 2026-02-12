use eframe::egui;
use std::fs;
use std::path::PathBuf;

pub struct Project {
    pub name: String,
    pub path: PathBuf,
}

pub struct ProjectsState {
    pub projects: Vec<Project>,
    pub show_window: bool,
}

pub enum ProjectAction {
    Open(PathBuf),
    Delete(PathBuf),
}

impl Default for ProjectsState {
    fn default() -> Self {
        Self {
            projects: Vec::new(),
            show_window: false,
        }
    }
}

impl ProjectsState {
    pub fn refresh(&mut self) {
        self.projects.clear();
        let appdata = if let Ok(appdata) = std::env::var("APPDATA") {
            PathBuf::from(appdata)
        } else {
            return;
        };

        let singularity_dir = appdata.join("Singularity");

        if singularity_dir.exists() {
            if let Ok(entries) = fs::read_dir(&singularity_dir) {
                for entry in entries.flatten() {
                    if let Ok(file_type) = entry.file_type() {
                        if file_type.is_dir() {
                            let name = entry.file_name().to_string_lossy().to_string();
                            // Filter out system folders
                            if name != "tools"
                                && name != "signatures"
                                && name != "logs"
                                && name != "CrashReports"
                            {
                                self.projects.push(Project {
                                    name,
                                    path: entry.path(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn show(&mut self, ctx: &egui::Context) -> Option<ProjectAction> {
        let mut action = None;
        let mut open = self.show_window;

        egui::Window::new("Projects")
            .open(&mut open)
            .show(ctx, |ui| {
                if ui.button("Refresh").clicked() {
                    self.refresh();
                }

                ui.separator();

                if self.projects.is_empty() {
                    ui.label("No projects found.");
                } else {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        for project in &self.projects {
                            ui.horizontal(|ui| {
                                ui.label(&project.name);
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if ui.button("Delete").clicked() {
                                            action =
                                                Some(ProjectAction::Delete(project.path.clone()));
                                        }
                                        if ui.button("Open").clicked() {
                                            action =
                                                Some(ProjectAction::Open(project.path.clone()));
                                        }
                                    },
                                );
                            });
                            ui.separator();
                        }
                    });
                }
            });

        self.show_window = open;
        action
    }
}
