use std::process::Command;
use std::thread;
use std::time::Duration;

const UPDATE_INTERVAL_SECS: u64 = 60 * 60 ; // 24 hores

pub fn start_update_loop() {
    thread::spawn(|| {
        loop {
            println!("Comprovant si toca actualitzar signatures...");

            match run_update_script() {
                Ok(output) => {
                    println!("Actualització completada correctament:");
                    println!("{}", output);
                }
                Err(error) => {
                    eprintln!("Error actualitzant signatures: {}", error);
                }
            }

            thread::sleep(Duration::from_secs(UPDATE_INTERVAL_SECS));
        }
    });
}

fn run_update_script() -> Result<String, String> {
    let output = Command::new("python")
        .arg("../scripts/update_signatures.py")
        .current_dir(".")
        .output()
        .map_err(|e| format!("No s'ha pogut executar el script: {}", e))?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        Err(stderr)
    }
}