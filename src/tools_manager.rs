use anyhow::{Context, Result};
use std::env;
use std::fs;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstallationStatus {
    Idle,
    Checking,
    InstallingNode(String), // message (ex: "Downloading Node.js...")
    InstallingPyArmor(String),
    InstallingSynchrony(String),
    Finished,
    Error(String),
}

pub struct ToolManager {
    pub status: Arc<Mutex<InstallationStatus>>,
}

impl ToolManager {
    pub fn global() -> &'static ToolManager {
        static MANAGER: OnceLock<ToolManager> = OnceLock::new();
        MANAGER.get_or_init(|| ToolManager {
            status: Arc::new(Mutex::new(InstallationStatus::Idle)),
        })
    }

    pub fn get_status(&self) -> InstallationStatus {
        if let Ok(s) = self.status.lock() {
            s.clone()
        } else {
            log!("ToolManager: Lock poisoned");
            InstallationStatus::Error("Lock poisoned".to_string())
        }
    }

    pub fn ensure_tools_available(&self) {
        log!("ToolManager: ensure_tools_available called");
        let status = self.get_status();
        if matches!(
            status,
            InstallationStatus::InstallingNode(_)
                | InstallationStatus::InstallingSynchrony(_)
                | InstallationStatus::Finished
        ) {
            log!("ToolManager: already installing or finished");
            return;
        }

        let status_arc = self.status.clone();
        thread::spawn(move || {
            log!("ToolManager: Starting installation thread");
            let res = perform_installation(&status_arc);
            let mut guard = status_arc.lock().unwrap();
            match res {
                Ok(_) => {
                    log!("ToolManager: Installation finished successfully");
                    *guard = InstallationStatus::Finished;
                }
                Err(e) => {
                    log!("ToolManager: Installation failed: {}", e);
                    *guard = InstallationStatus::Error(e.to_string());
                }
            }
        });
    }

    pub fn get_tools_dir(&self) -> PathBuf {
        let base = env::var_os("APPDATA")
            .or_else(|| env::var_os("LOCALAPPDATA"))
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir);
        base.join("Singularity").join("tools")
    }

    pub fn get_extracted_dir(&self) -> PathBuf {
        let tools_dir = self.get_tools_dir();
        tools_dir.parent().unwrap().join("extracted")
    }

    pub fn get_or_download_tool(
        &self,
        tool_id: &str,
        url: &str,
        file_name: &str,
    ) -> Result<PathBuf> {
        let tools_dir = self.get_tools_dir();
        fs::create_dir_all(&tools_dir)?;

        let dst = tools_dir.join(file_name);
        if dst.exists() {
            return Ok(dst);
        }

        let response =
            reqwest::blocking::get(url).with_context(|| format!("{tool_id} download"))?;
        if !response.status().is_success() {
            anyhow::bail!("{tool_id} download failed: status {}", response.status());
        }
        let bytes = response
            .bytes()
            .with_context(|| format!("{tool_id} download bytes"))?;

        let tmp = tools_dir.join(format!(
            "{tool_id}.{}.tmp",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        ));
        fs::write(&tmp, &bytes).with_context(|| format!("{tool_id} write tmp"))?;
        fs::rename(&tmp, &dst).or_else(|_| {
            let _ = fs::remove_file(&dst);
            fs::rename(&tmp, &dst)
        })?;

        Ok(dst)
    }

    // get_python_path removed
    pub fn setup_python(&self, version: (u8, u8)) -> Result<PathBuf> {
        let (major, minor) = version;
        // Map version to embedded python URL
        let url = match (major, minor) {
            (3, 5) => "https://www.python.org/ftp/python/3.5.4/python-3.5.4-embed-amd64.zip",
            (3, 6) => "https://www.python.org/ftp/python/3.6.8/python-3.6.8-embed-amd64.zip",
            (3, 7) => "https://www.python.org/ftp/python/3.7.9/python-3.7.9-embed-amd64.zip",
            (3, 8) => "https://www.python.org/ftp/python/3.8.10/python-3.8.10-embed-amd64.zip",
            (3, 9) => "https://www.python.org/ftp/python/3.9.13/python-3.9.13-embed-amd64.zip",
            (3, 10) => "https://www.python.org/ftp/python/3.10.11/python-3.10.11-embed-amd64.zip",
            (3, 11) => "https://www.python.org/ftp/python/3.11.9/python-3.11.9-embed-amd64.zip",
            (3, 12) => "https://www.python.org/ftp/python/3.12.3/python-3.12.3-embed-amd64.zip",
            (3, 13) => "https://www.python.org/ftp/python/3.13.0/python-3.13.0-embed-amd64.zip",
            (3, 14) => "https://www.python.org/ftp/python/3.14.0/python-3.14.0-embed-amd64.zip",
            _ => "https://www.python.org/ftp/python/3.11.9/python-3.11.9-embed-amd64.zip", // Default fallback
        };

        let tool_id = format!("python-{}.{}", major, minor);
        let zip_filename = format!("{}.zip", tool_id);

        // Download the zip file
        let zip_path = self.get_or_download_tool(&tool_id, url, &zip_filename)?;

        // Setup extraction directory
        let tools_dir = zip_path.parent().unwrap();
        let extract_dir = tools_dir.join(&tool_id);
        let python_exe = extract_dir.join("python.exe");

        if !python_exe.exists() {
            // Extract if not exists
            let file = fs::File::open(&zip_path).context("Failed to open python zip")?;
            let mut archive = zip::ZipArchive::new(file).context("Failed to read python zip")?;

            fs::create_dir_all(&extract_dir).context("Failed to create extract dir")?;
            archive
                .extract(&extract_dir)
                .context("Failed to extract python zip")?;
        }

        // Ensure dependencies are installed
        self.install_python_dependencies(&python_exe, version)?;

        Ok(python_exe)
    }

    fn install_python_dependencies(&self, python_exe: &PathBuf, version: (u8, u8)) -> Result<()> {
        let python_dir = python_exe.parent().unwrap();
        let marker = python_dir.join(".deps_installed_v1");
        if marker.exists() {
            return Ok(());
        }

        // 1. Enable site in ._pth
        for entry in fs::read_dir(python_dir)? {
            let entry = entry?;
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "_pth" {
                    let content = fs::read_to_string(&path)?;
                    if content.contains("#import site") {
                        let new_content = content.replace("#import site", "import site");
                        fs::write(&path, new_content)?;
                    }
                }
            }
        }

        // 2. Download get-pip.py
        let get_pip_url = match version {
            (3, 5) => "https://bootstrap.pypa.io/pip/3.5/get-pip.py",
            (3, 6) => "https://bootstrap.pypa.io/pip/3.6/get-pip.py",
            _ => "https://bootstrap.pypa.io/get-pip.py",
        };
        let get_pip_path = python_dir.join("get-pip.py");
        if !get_pip_path.exists() {
            let resp = reqwest::blocking::get(get_pip_url)?.bytes()?;
            fs::write(&get_pip_path, &resp)?;
        }

        // 3. Install pip
        let mut cmd = Command::new(python_exe);
        #[cfg(windows)]
        cmd.creation_flags(0x08000000);
        let status = cmd.arg(&get_pip_path).status()?;
        if !status.success() {
            log!("Warning: get-pip.py failed or pip already installed");
        }

        // 4. Install pycryptodome
        let mut cmd = Command::new(python_exe);
        #[cfg(windows)]
        cmd.creation_flags(0x08000000);
        let status = cmd
            .args([
                "-m",
                "pip",
                "install",
                "pycryptodome",
                "--no-warn-script-location",
            ])
            .status()?;

        if status.success() {
            fs::write(&marker, "ok")?;
        } else {
            anyhow::bail!("Failed to install pycryptodome");
        }

        Ok(())
    }

    pub fn is_pyarmor_oneshot_available(&self) -> bool {
        let tools_dir = self.get_tools_dir();
        let oneshot_dir = tools_dir.join("pyarmor-1shot");
        let exe_path = oneshot_dir.join("pyarmor-1shot.exe");
        let script_path = oneshot_dir.join("shot.py");
        exe_path.exists() && script_path.exists()
    }

    pub fn setup_pyarmor_oneshot(&self) -> Result<PathBuf> {
        let tool_id = "pyarmor-1shot-v0.2.2";
        let url = "https://github.com/Lil-House/Pyarmor-Static-Unpack-1shot/releases/download/v0.2.2/pyarmor-1shot-v0.2.2-windows-x86_64.zip";
        let zip_filename = "pyarmor-1shot.zip";

        let tools_dir = self.get_tools_dir();
        let oneshot_dir = tools_dir.join("pyarmor-1shot");
        let exe_path = oneshot_dir.join("pyarmor-1shot.exe");
        let script_path = oneshot_dir.join("shot.py");

        if exe_path.exists() && script_path.exists() {
            // Ensure wrapper exists too
            let wrapper_path = tools_dir.join("pyarmor_wrapper.py");
            if !wrapper_path.exists() {
                self.create_pyarmor_wrapper(&wrapper_path)?;
            }
            return Ok(exe_path);
        }

        let initial_status = self.get_status();
        let should_cleanup = matches!(
            initial_status,
            InstallationStatus::Idle | InstallationStatus::Finished
        );

        if let Ok(mut guard) = self.status.lock() {
            *guard =
                InstallationStatus::InstallingPyArmor("Setting up PyArmor OneShot...".to_string());
        }

        if !exe_path.exists() {
            // Trigger download - this will download to APPDATA cache if we use get_or_download_tool
            // But we want to install to CWD/tools.
            // We can still use get_or_download_tool to get the ZIP path (it caches in APPDATA),
            // and then extract to CWD/tools.
            let zip_path = self.get_or_download_tool(tool_id, url, zip_filename)?;
            // get_or_download_tool returns path to zip in APPDATA/Singularity/tools/pyarmor-1shot.zip (cache)

            fs::create_dir_all(&oneshot_dir)?;

            // Extract zip
            let file = fs::File::open(&zip_path).context("Failed to open pyarmor zip")?;
            let mut archive = zip::ZipArchive::new(file).context("Failed to read pyarmor zip")?;
            archive
                .extract(&oneshot_dir)
                .context("Failed to extract pyarmor zip")?;

            // The ZIP might contain a top-level folder (e.g. "pyarmor-1shot-v0.2.2-windows-x86_64").
            // We need to move files up if they are in a subdirectory.
            // First, find where pyarmor-1shot.exe ended up.
            let mut root_of_files = oneshot_dir.clone();
            for entry in walkdir::WalkDir::new(&oneshot_dir) {
                if let Ok(entry) = entry {
                    if entry.file_name().to_string_lossy() == "pyarmor-1shot.exe" {
                        root_of_files = entry.path().parent().unwrap().to_path_buf();
                        break;
                    }
                }
            }

            // If files are in a subdirectory, move them up
            if root_of_files != oneshot_dir {
                for entry in fs::read_dir(&root_of_files)? {
                    let entry = entry?;
                    let path = entry.path();
                    let file_name = entry.file_name();
                    let dest = oneshot_dir.join(file_name);
                    if !dest.exists() {
                        fs::rename(path, dest)?;
                    }
                }
                // Try to remove the now empty subdir
                let _ = fs::remove_dir_all(root_of_files);
            }
        }

        if !script_path.exists() {
            let base_url = "https://raw.githubusercontent.com/Lil-House/Pyarmor-Static-Unpack-1shot/main/oneshot";
            let files = [
                "shot.py",
                "detect.py",
                "runtime.py",
                "util.py",
                "__init__.py",
            ];

            for file in files {
                let file_url = format!("{base_url}/{file}");
                let resp = reqwest::blocking::get(&file_url)?.text()?;
                fs::write(oneshot_dir.join(file), resp)?;
            }
        }

        // Create wrapper script
        let wrapper_path = tools_dir.join("pyarmor_wrapper.py");
        self.create_pyarmor_wrapper(&wrapper_path)?;

        if should_cleanup {
            if let Ok(mut guard) = self.status.lock() {
                *guard = InstallationStatus::Finished;
            }
        }

        Ok(exe_path)
    }

    fn create_pyarmor_wrapper(&self, path: &std::path::Path) -> Result<()> {
        let content = r#"
import sys
import os
import shutil
import subprocess

def find_runtime(root):
    candidates = []
    for dirpath, dirnames, filenames in os.walk(root):
        for f in filenames:
            if f.startswith("pyarmor_runtime"):
                candidates.append(os.path.join(dirpath, f))
    return candidates[0] if candidates else None

def main():
    if len(sys.argv) < 3:
        print("Usage: wrapper.py <input_path> <output_dir>")
        sys.exit(1)

    input_path = sys.argv[1]
    output_dir = sys.argv[2]

    if os.path.isfile(input_path):
        work_dir = os.path.dirname(os.path.abspath(input_path))
    else:
        work_dir = os.path.abspath(input_path)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    oneshot_dir = os.path.join(base_dir, "pyarmor-1shot")
    shot_script = os.path.join(oneshot_dir, "shot.py")
    
    if not os.path.exists(shot_script):
        print(f"Error: shot.py not found at {shot_script}")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    runtime = find_runtime(work_dir)
    cmd = [sys.executable, shot_script, input_path, "-o", output_dir]
    if runtime:
        cmd.extend(["-r", runtime])

    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=work_dir, capture_output=True, text=True)
    
    print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    
    if result.returncode != 0:
        sys.exit(result.returncode)

if __name__ == "__main__":
    main()
"#;
        fs::write(path, content.trim())?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn setup_pyinstxtractor(&self) -> Result<PathBuf> {
        let tool_id = "pyinstxtractor-master";
        let url = "https://raw.githubusercontent.com/extremecoders-re/pyinstxtractor/master/pyinstxtractor.py";
        let filename = "pyinstxtractor.py";

        let script_path = self.get_or_download_tool(tool_id, url, filename)?;
        Ok(script_path)
    }

    pub fn setup_7zip(&self) -> Result<PathBuf> {
        // 1. Check common locations
        let common_paths = [
            r"C:\Program Files\7-Zip\7z.exe",
            r"C:\Program Files (x86)\7-Zip\7z.exe",
        ];
        for p in common_paths {
            if std::path::Path::new(p).exists() {
                return Ok(PathBuf::from(p));
            }
        }

        // 2. Check PATH
        if is_command_available("7z") {
            return Ok(PathBuf::from("7z"));
        }

        // 3. Install portable (via installer /S /D=...)
        let tool_id = "7zip-24.08";
        let filename = "7z2408-x64.exe";
        let url = "https://www.7-zip.org/a/7z2408-x64.exe";

        let installer_path = self.get_or_download_tool(tool_id, url, filename)?;
        let tools_dir = installer_path.parent().unwrap();
        let install_dir = tools_dir.join("7Zip");
        let seven_z_exe = install_dir.join("7z.exe");

        if seven_z_exe.exists() {
            return Ok(seven_z_exe);
        }

        // Run installer silently
        let mut cmd = Command::new(&installer_path);
        #[cfg(windows)]
        cmd.creation_flags(0x08000000);

        let install_dir_str = install_dir.to_string_lossy().to_string();
        cmd.arg("/S").arg(format!("/D={}", install_dir_str));

        let status = cmd.status().context("Failed to run 7-Zip installer")?;
        if !status.success() {
            anyhow::bail!("7-Zip installer failed");
        }

        if !seven_z_exe.exists() {
            anyhow::bail!("7-Zip installed but 7z.exe not found at expected location");
        }

        Ok(seven_z_exe)
    }
}

fn perform_installation(status: &Arc<Mutex<InstallationStatus>>) -> Result<()> {
    // 1. Check if Node is installed
    {
        let mut guard = status.lock().unwrap();
        *guard = InstallationStatus::Checking;
    }

    let _node_path = if !is_command_available("node") {
        {
            let mut guard = status.lock().unwrap();
            *guard = InstallationStatus::InstallingNode("Downloading Node.js...".to_string());
        }
        let installed_path = install_node_portable(status)?;

        // Add to PATH for current process
        let path_env = env::var_os("PATH").unwrap_or_default();
        let mut paths = env::split_paths(&path_env).collect::<Vec<_>>();
        paths.insert(0, installed_path.clone());
        let new_path = env::join_paths(paths)?;
        unsafe {
            env::set_var("PATH", new_path);
        }

        Some(installed_path)
    } else {
        None
    };

    // 2. Check/Install PyArmor OneShot
    {
        let mut guard = status.lock().unwrap();
        *guard = InstallationStatus::InstallingPyArmor("Checking...".to_string());
    }
    ToolManager::global().setup_pyarmor_oneshot().ok();

    // 3. Check/Install Synchrony
    {
        let mut guard = status.lock().unwrap();
        *guard = InstallationStatus::InstallingSynchrony(
            "Installing analysis tools (synchrony/asar)...".to_string(),
        );
    }

    // Use npm to install deobfuscator
    let npm_cmd = if cfg!(windows) { "npm.cmd" } else { "npm" };

    // Check if already installed
    if !is_command_available("synchrony") && !is_command_available("deobfuscator") {
        let mut cmd = Command::new(npm_cmd);
        #[cfg(windows)]
        cmd.creation_flags(0x08000000);
        cmd.args(["install", "--global", "deobfuscator"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let output = cmd.output().context("Failed to run npm install")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("npm install failed: {}", stderr);
        }
    }

    if !is_command_available("asar") && !is_command_available("asar.cmd") {
        let mut cmd = Command::new(npm_cmd);
        #[cfg(windows)]
        cmd.creation_flags(0x08000000);
        cmd.args(["install", "--global", "asar"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let output = cmd.output().context("Failed to run npm install (asar)")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("npm install (asar) failed: {}", stderr);
        }
    }

    if let Some(bin_dir) = npm_global_bin_dir(npm_cmd)? {
        add_dir_to_process_path(bin_dir)?;
    }

    Ok(())
}

fn npm_global_bin_dir(npm_cmd: &str) -> Result<Option<PathBuf>> {
    let mut cmd = Command::new(npm_cmd);
    #[cfg(windows)]
    cmd.creation_flags(0x08000000);
    let out = cmd
        .args(["bin", "-g"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    let Ok(out) = out else {
        return Ok(None);
    };
    if !out.status.success() {
        return Ok(None);
    }

    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        return Ok(None);
    }
    Ok(Some(PathBuf::from(s)))
}

fn add_dir_to_process_path(dir: PathBuf) -> Result<()> {
    let path_env = env::var_os("PATH").unwrap_or_default();
    let mut paths = env::split_paths(&path_env).collect::<Vec<_>>();
    if paths.iter().any(|p| p == &dir) {
        return Ok(());
    }
    paths.insert(0, dir);
    let new_path = env::join_paths(paths)?;
    unsafe {
        env::set_var("PATH", new_path);
    }
    Ok(())
}

pub fn is_command_available(cmd: &str) -> bool {
    let check_cmd = if cfg!(windows) { "where" } else { "which" };
    let mut command = Command::new(check_cmd);
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    command
        .arg(cmd)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn install_node_portable(status: &Arc<Mutex<InstallationStatus>>) -> Result<PathBuf> {
    // Download URL for Node.js Windows x64 binary zip
    // Using a specific LTS version for stability (v20.11.0 is a good LTS candidate, or v18)
    // Let's use v20.11.0
    let url = "https://nodejs.org/dist/v20.11.0/node-v20.11.0-win-x64.zip";
    let app_data = env::var("APPDATA").context("APPDATA not set")?;
    let install_dir = PathBuf::from(app_data).join("Singularity").join("tools");

    if !install_dir.exists() {
        fs::create_dir_all(&install_dir)?;
    }

    let zip_path = install_dir.join("node.zip");

    // Download
    let response = reqwest::blocking::get(url)?;
    if !response.status().is_success() {
        anyhow::bail!("Failed to download Node.js: status {}", response.status());
    }
    let content = response.bytes()?;
    fs::write(&zip_path, &content)?;

    // Update status
    {
        let mut guard = status.lock().unwrap();
        *guard = InstallationStatus::InstallingNode("Extracting Node.js...".to_string());
    }

    // Extract
    let file = fs::File::open(&zip_path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    // The zip contains a top-level folder "node-v20.11.0-win-x64"
    // We want to extract it and return that path
    archive.extract(&install_dir)?;

    // Clean up zip
    let _ = fs::remove_file(&zip_path);

    let extracted_folder = install_dir.join("node-v20.11.0-win-x64");
    if !extracted_folder.exists() {
        anyhow::bail!(
            "Extraction failed: folder not found at {:?}",
            extracted_folder
        );
    }

    Ok(extracted_folder)
}
