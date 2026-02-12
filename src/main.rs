#![windows_subsystem = "windows"]

#[macro_use]
mod log;

mod analysis;
mod app;
mod asar_ripper;
mod deobfuscator;
mod detect_type_file;
mod disassemble;
mod export;
mod extractor;
mod heuristic_decryptor;
mod js_deobfuscator;
mod js_sandbox;
mod js_sandbox_ui;
mod layered_analysis;
mod link_decryptor;
mod malware;
mod misc_tools;
mod online_scanner;
mod projects;
mod secrets;
mod signature_engine;
mod tools_manager;
mod update_rules;

#[cfg(windows)]
use windows::Win32::System::Console::{ATTACH_PARENT_PROCESS, AttachConsole};

fn load_icon() -> eframe::egui::IconData {
    let (icon_rgba, icon_width, icon_height) = {
        let icon = include_bytes!("../Singularity.png");
        let image = image::load_from_memory(icon)
            .expect("Failed to open icon path")
            .into_rgba8();
        let (width, height) = image.dimensions();
        let rgba = image.into_raw();
        (rgba, width, height)
    };

    eframe::egui::IconData {
        rgba: icon_rgba,
        width: icon_width,
        height: icon_height,
    }
}

fn main() -> eframe::Result<()> {
    // Attach to parent console if possible (for CLI usage)
    #[cfg(windows)]
    unsafe {
        if !AttachConsole(ATTACH_PARENT_PROCESS).as_bool() {
            // If failed, we might want to alloc a console ONLY if args imply CLI usage?
            // But usually if started from Explorer, args.len() == 1.
            // If started from cmd/powershell, AttachConsole should work.
        }
    }

    log::init();
    std::panic::set_hook(Box::new(|info| {
        let msg = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown panic payload".to_string());
        let loc = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "-".to_string());
        let full = format!("panic at {loc}\n{msg}");
        let _ = app::write_error_log(
            "panic hook",
            &full,
            std::backtrace::Backtrace::force_capture(),
        );
    }));

    // WGPU diagnostic removed to clean output, but we know the issue is missing adapter.
    // std::env::set_var("WGPU_ Log_LEVEL", "Warn"); // Clean WGPU logs

    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && !args[1].starts_with("--") {
        let path = std::path::Path::new(&args[1]);
        if path.exists() {
            println!("Singularity CLI Mode");
            println!("Analyzing: {:?}", path);

            let engine = analysis::AnalysisEngine::default();
            let mut progress = |p: analysis::AnalysisProgress| {
                println!("[{}] {:.0}%", p.step, p.fraction * 100.0);
            };

            match engine.analyze_file_with_progress(path, &mut progress) {
                Ok(res) => {
                    println!("\nAnalysis Result:");
                    println!("Format: {}", res.file_format);
                    println!("Language: {}", res.language);
                    println!("Kind: {}", res.kind);
                    println!("Confidence: {}/100", res.confidence_score);
                    if !res.warnings.is_empty() {
                        println!("Warnings: {:?}", res.warnings);
                    }
                    if !res.yara_matches.is_empty() {
                        println!("YARA Matches: {:?}", res.yara_matches);
                    }
                    if !res.secrets.is_empty() {
                        println!("Secrets Found: {:?}", res.secrets);
                    }
                    if let Some(report) = &res.layered_report {
                        println!("Layered Analysis Report:");

                        // Collect and dedup all extracted files
                        let mut all_extracted_files = std::collections::BTreeSet::new();
                        for layer in &report.layers {
                            for file in &layer.extracted_files {
                                all_extracted_files.insert(file);
                            }
                        }

                        if !all_extracted_files.is_empty() {
                            println!("Extracted Files:");
                            for file in &all_extracted_files {
                                println!("  - {}", file);
                            }
                            println!();
                        }

                        for layer in &report.layers {
                            println!("  - Type: {:?}, Method: {}", layer.layer_type, layer.method);
                            println!("    Details: {}", layer.details);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error during analysis: {:?}", e);
                }
            }
            return Ok(());
        }
    }

    let native_options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_min_inner_size([800.0, 600.0])
            .with_icon(load_icon()),
        wgpu_options: eframe::egui_wgpu::WgpuConfiguration {
            supported_backends: wgpu::Backends::DX12 | wgpu::Backends::GL,
            ..Default::default()
        },
        ..Default::default()
    };

    match eframe::run_native(
        "Singularity - Advanced Reverse Engineering Tool",
        native_options,
        Box::new(|cc| {
            app::configure_theme(&cc.egui_ctx);
            let mut app = app::SingularityApp::default();
            app.load_settings();
            app.start_background_tasks();
            Box::new(app)
        }),
    ) {
        Ok(_) => {}
        Err(e) => {
            // If it crashes immediately (often due to WGPU/Graphics on VM),
            // we try to show a classic Windows MessageBox so the user understands why.
            let msg = format!(
                "Critical Graphic Startup Error:\n{}\n\nYour system (VM/RDP) does not seem to have a compatible graphics card (OpenGL 2.0+ or DirectX).\n\nSOLUTION:\n1. Download 'Mesa3D for Windows' (MSVC release).\n2. Extract the 'opengl32.dll' file (x64 folder).\n3. Place the 'opengl32.dll' file next to Singularity.exe.\nThis will enable software rendering.",
                e
            );

            #[cfg(target_os = "windows")]
            unsafe {
                use std::ffi::OsStr;
                use std::os::windows::ffi::OsStrExt;
                use windows::{Win32::UI::WindowsAndMessaging::*, core::*};

                let wide_msg: Vec<u16> = OsStr::new(&msg)
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();
                let wide_title: Vec<u16> = OsStr::new("Singularity - Graphic Error")
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();

                MessageBoxW(
                    None,
                    PCWSTR(wide_msg.as_ptr()),
                    PCWSTR(wide_title.as_ptr()),
                    MB_OK | MB_ICONERROR,
                );
            }
            eprintln!("Startup error: {}", e);
        }
    }

    Ok(())
}
