use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::models::{Detection, ScanResult, AppConfig};
use crate::signatures::{self, SignaturesMap};
use crate::yara_engine::YaraEngine;


pub fn scan_path(
    path_str: &str,
    signatures_map: &SignaturesMap,
    yara_engine: &YaraEngine,
    config: &AppConfig,
) -> Result<ScanResult, String> {
    let path = Path::new(path_str);

    if !path.exists() {
        return Err("El path no existeix".to_string());
    }

    let mut result = ScanResult {
        scanned_files: 0,
        detections: Vec::new(),
    };

    let mut seen_detections = HashSet::new();

    scan_recursive(path, &mut result, &mut seen_detections, signatures_map, yara_engine, config)?;

    Ok(result)
}

fn scan_recursive(
    path: &Path,
    result: &mut ScanResult,
    seen_detections: &mut HashSet<String>,
    signatures_map: &SignaturesMap,
    yara_engine: &YaraEngine,
    config: &AppConfig,
) -> Result<(), String> {
    if path.is_file() {
        result.scanned_files += 1;

        let path_str = path.to_string_lossy().to_string();

        if let Some(signature) = signatures::check_file_signature(&path_str, signatures_map)? {
            add_detection(
                result,
                seen_detections,
                Detection {
                    path: path_str.clone(),
                    engine: "hash".to_string(),
                    name: signature.name,
                    category: "known_malware".to_string(),
                    severity: signature.severity,
                    confidence: signature.confidence,
                    source: signature.source,
                },
            );
        }

        let metadata = fs::metadata(path)
            .map_err(|e| format!("No es pot llegir metadata del fitxer: {}", e))?;

        let max_size_bytes = config.max_yara_file_size_mb * 1024 * 1024;

        if metadata.len() <= max_size_bytes {
            let yara_detections = yara_engine.scan_file(&path_str)?;

            for detection in yara_detections {
                add_detection(result, seen_detections, detection);
            }
        }

        return Ok(());
    }

    if path.is_dir() {
        let entries = fs::read_dir(path)
            .map_err(|_| format!("No es pot llegir el directori: {}", path.to_string_lossy()))?;

        for entry in entries {
            let entry = entry.map_err(|_| "Error llegint entrada del directori".to_string())?;
            let entry_path = entry.path();

            scan_recursive(
                &entry_path,
                result,
                seen_detections,
                signatures_map,
                yara_engine,
                config,
            )?;
        }

        return Ok(());
    }

    Ok(())
}

fn add_detection(
    result: &mut ScanResult,
    seen_detections: &mut HashSet<String>,
    detection: Detection,
) {
    let key = format!(
        "{}:{}:{}",
        detection.path, detection.engine, detection.name
    );

    if seen_detections.insert(key) {
        result.detections.push(detection);
    }
}



pub fn scan_path_with_progress<F>(
    path_str: &str,
    signatures_map: &SignaturesMap,
    yara_engine: &YaraEngine,
    config: &AppConfig,
    mut on_progress: F,
) -> Result<ScanResult, String>
where
    F: FnMut(usize, usize) -> Result<(), String>,
{
    let path = Path::new(path_str);

    if !path.exists() {
        return Err("El path no existeix".to_string());
    }

    let total_files = count_files(path)?;

    let mut result = ScanResult {
        scanned_files: 0,
        detections: Vec::new(),
    };

    let mut seen_detections = HashSet::new();

    scan_recursive_with_progress(
        path,
        &mut result,
        &mut seen_detections,
        signatures_map,
        yara_engine,
        config,
        total_files,
        &mut on_progress,
    )?;

    Ok(result)
}

fn count_files(path: &Path) -> Result<usize, String> {
    if path.is_file() {
        return Ok(1);
    }

    if path.is_dir() {
        let mut total = 0;

        let entries = fs::read_dir(path)
            .map_err(|_| format!("No es pot llegir el directori: {}", path.to_string_lossy()))?;

        for entry in entries {
            let entry = entry.map_err(|_| "Error llegint entrada del directori".to_string())?;
            total += count_files(&entry.path())?;
        }

        return Ok(total);
    }

    Ok(0)
}

fn scan_recursive_with_progress<F>(
    path: &Path,
    result: &mut ScanResult,
    seen_detections: &mut HashSet<String>,
    signatures_map: &SignaturesMap,
    yara_engine: &YaraEngine,
    config: &AppConfig,
    total_files: usize,
    on_progress: &mut F,
) -> Result<(), String>
where
    F: FnMut(usize, usize) -> Result<(), String>,
{
    if path.is_file() {
        result.scanned_files += 1;

        let path_str = path.to_string_lossy().to_string();

        if let Some(signature) = signatures::check_file_signature(&path_str, signatures_map)? {
            add_detection(
                result,
                seen_detections,
                Detection {
                    path: path_str.clone(),
                    engine: "hash".to_string(),
                    name: signature.name,
                    category: "known_malware".to_string(),
                    severity: signature.severity,
                    confidence: signature.confidence,
                    source: signature.source,
                },
            );
        }

        let metadata = fs::metadata(path)
            .map_err(|e| format!("No es pot llegir metadata del fitxer: {}", e))?;

        let max_size_bytes = config.max_yara_file_size_mb * 1024 * 1024;

        if metadata.len() <= max_size_bytes {
            let yara_detections = yara_engine.scan_file(&path_str)?;

            for detection in yara_detections {
                add_detection(result, seen_detections, detection);
            }
        }

        on_progress(result.scanned_files, total_files)?;

        return Ok(());
    }

    if path.is_dir() {
        let entries = fs::read_dir(path)
            .map_err(|_| format!("No es pot llegir el directori: {}", path.to_string_lossy()))?;

        for entry in entries {
            let entry = entry.map_err(|_| "Error llegint entrada del directori".to_string())?;

            scan_recursive_with_progress(
                &entry.path(),
                result,
                seen_detections,
                signatures_map,
                yara_engine,
                config,
                total_files,
                on_progress,
            )?;
        }
    }

    Ok(())
}