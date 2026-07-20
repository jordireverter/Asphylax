use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use crate::paths;

const UPDATE_INTERVAL_SECS: u64 = 60 * 60; // 1 hora

pub fn start_update_loop() {
    thread::spawn(|| loop {
        println!("Comprovant si toca actualitzar signatures...");

        match run_update_script() {
            Ok(output) => {
                if !output.trim().is_empty() {
                    println!("{}", output);
                }
            }
            Err(error) => {
                eprintln!("Error actualitzant signatures: {}", error);
            }
        }

        thread::sleep(Duration::from_secs(UPDATE_INTERVAL_SECS));
    });
}

fn run_update_script() -> Result<String, String> {
    let project_root = paths::project_root();
    let Some(python) = find_python(&project_root) else {
        return Ok(
            "No s'ha trobat cap intèrpret Python funcional; s'omet l'actualització automàtica."
                .to_string(),
        );
    };

    let output = Command::new(python)
        .arg(paths::script_file("update_signatures.py"))
        .current_dir(project_root)
        .output()
        .map_err(|e| format!("No s'ha pogut executar el script: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

fn find_python(project_root: &Path) -> Option<PathBuf> {
    let candidates = [
        project_root.join(".venv").join("Scripts").join("python.exe"),
        PathBuf::from("python"),
        PathBuf::from("python3"),
    ];

    candidates.into_iter().find(python_works)
}

fn python_works(candidate: &PathBuf) -> bool {
    Command::new(candidate)
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}
