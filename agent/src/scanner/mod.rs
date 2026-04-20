use std::fs;
use std::path::Path;

use crate::models::ScanResult;
use crate::signatures;

pub fn scan_path(path_str: &str) -> Result<ScanResult, String> {
    let path = Path::new(path_str);

    if !path.exists() {
        return Err("El path no existeix".to_string());
    }

    let mut result = ScanResult {
        scanned_files: 0,
        detections: Vec::new(),
    };

    scan_recursive(path, &mut result)?;

    Ok(result)
}

fn scan_recursive(path: &Path, result: &mut ScanResult) -> Result<(), String> {
    if path.is_file() {
        result.scanned_files += 1;

        let path_str = path.to_string_lossy();

        match signatures::check_file_signature(&path_str)? {
            Some(name) => {
                result
                    .detections
                    .push(format!("{} -> {}", path_str, name));
            }
            None => {}
        }

        return Ok(());
    }

    if path.is_dir() {
        let entries = fs::read_dir(path)
            .map_err(|_| format!("No es pot llegir el directori: {}", path.to_string_lossy()))?;

        for entry in entries {
            let entry = entry.map_err(|_| "Error llegint entrada del directori".to_string())?;
            let entry_path = entry.path();

            scan_recursive(&entry_path, result)?;
        }

        return Ok(());
    }

    Ok(())
}