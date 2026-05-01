use std::fs;
use std::path::Path;

use crate::models::ScanResult;
use crate::signatures::{self, SignaturesMap};
use crate::yara_engine::YaraEngine;

pub fn scan_path(
    path_str: &str,
    signatures_map: &SignaturesMap,
    yara_engine: &YaraEngine,
) -> Result<ScanResult, String> {
    let path = Path::new(path_str);

    if !path.exists() {
        return Err("El path no existeix".to_string());
    }

    let mut result = ScanResult {
        scanned_files: 0,
        detections: Vec::new(),
    };

    scan_recursive(path, &mut result, signatures_map, yara_engine)?;

    Ok(result)
}

fn scan_recursive(
    path: &Path,
    result: &mut ScanResult,
    signatures_map: &SignaturesMap,
    yara_engine: &YaraEngine,
) -> Result<(), String> {
    if path.is_file() {
        result.scanned_files += 1;

        let path_str = path.to_string_lossy();

        match signatures::check_file_signature(&path_str, signatures_map)? {
            Some(name) => {
                result
                    .detections
                    .push(format!("{} -> signatura exacta: {}", path_str, name));
            }
            None => {}
        }

        let yara_detections = yara_engine.scan_file(&path_str)?;

        for rule_name in yara_detections {
            result
                .detections
                .push(format!("{} -> regla YARA: {}", path_str, rule_name));
        }

        return Ok(());
    }

    if path.is_dir() {
        let entries = fs::read_dir(path)
            .map_err(|_| format!("No es pot llegir el directori: {}", path.to_string_lossy()))?;

        for entry in entries {
            let entry = entry.map_err(|_| "Error llegint entrada del directori".to_string())?;
            let entry_path = entry.path();

            scan_recursive(&entry_path, result, signatures_map, yara_engine)?;
        }

        return Ok(());
    }

    Ok(())
}