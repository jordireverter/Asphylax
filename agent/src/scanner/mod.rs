use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use rayon::prelude::*;

use crate::decision_engine;
use crate::heuristics;
use crate::models::{AppConfig, Detection, FileScanResult, ScanResult};
use crate::pe_analysis;
use crate::signatures::{self, SignaturesMap};
use crate::yara_engine::YaraEngine;
use crate::quarantine;

pub fn scan_path(
    path_str: &str,
    signatures_map: &SignaturesMap,
    yara_engine: &YaraEngine,
    config: &AppConfig,
) -> Result<ScanResult, String> {
    scan_path_with_progress(
        path_str,
        signatures_map,
        yara_engine,
        config,
        |_scanned, _total| Ok(()),
    )
}

pub fn scan_path_with_progress<F>(
    path_str: &str,
    signatures_map: &SignaturesMap,
    yara_engine: &YaraEngine,
    config: &AppConfig,
    on_progress: F,
) -> Result<ScanResult, String>
where
    F: Fn(usize, usize) -> Result<(), String> + Sync,
{
    let path = Path::new(path_str);

    if !path.exists() {
        return Err("El path no existeix".to_string());
    }

    let mut files = Vec::new();
    let options = ScanOptions { quick_scan: false };
    collect_files(path, &mut files, config, &options)?;

    let total_files = files.len();

    if total_files == 0 {
        return Ok(ScanResult {
            scanned_files: 0,
            total_detections: 0,
            final_score: 0,
            classification: "clean".to_string(),
            files: Vec::new(),
        });
    }

    let scanned_counter = AtomicUsize::new(0);
    let last_percent_sent = AtomicUsize::new(0);

    let partial_results: Result<Vec<FileScanResult>, String> = files
        .par_iter()
        .map(|file_path| {
            let file_result = scan_single_file(file_path, signatures_map, yara_engine, config)?;

            let scanned = scanned_counter.fetch_add(1, Ordering::SeqCst) + 1;
            let percent = (scanned * 100) / total_files;

            let mut previous = last_percent_sent.load(Ordering::SeqCst);

            while percent > previous {
                match last_percent_sent.compare_exchange(
                    previous,
                    percent,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => {
                        on_progress(scanned, total_files)?;
                        break;
                    }
                    Err(current) => previous = current,
                }
            }

            Ok(file_result)
        })
        .collect();

    let mut file_results = partial_results?;

    file_results.retain(|file| !file.detections.is_empty());

    let total_detections = file_results
        .iter()
        .map(|file| file.detections.len())
        .sum::<usize>();

    let final_score = file_results
        .iter()
        .map(|file| file.final_score)
        .max()
        .unwrap_or(0);

    let classification = classify_global(final_score).to_string();
    
    if config.auto_quarantine.enabled {
        for file in &mut file_results {
            if should_auto_quarantine(&file.classification, &config.auto_quarantine.minimum_classification) {
                match quarantine::quarantine_file(&file.path) {
                    Ok(_) => {
                        file.classification = "quarantined".to_string();
                    }
                    Err(error) => {
                        eprintln!("No s'ha pogut posar en quarantena {}: {}", file.path, error);
                    }
                }
            }
        }
    }

    Ok(ScanResult {
        scanned_files: total_files,
        total_detections,
        final_score,
        classification,
        files: file_results,
    })
}

fn collect_files(path: &Path, files: &mut Vec<PathBuf>, config: &AppConfig, options: &ScanOptions) -> Result<(), String> {
    if path.is_file() {
        files.push(path.to_path_buf());
        return Ok(());
    }
    if is_excluded(path, config) {
        return Ok(());
    }

    if options.quick_scan && path.is_file() {
        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return Ok(()),
        };

        let max_size = config.quick_scan.max_file_size_mb * 1024 * 1024;

        if metadata.len() > max_size {
            return Ok(());
        }

        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| format!(".{}", e.to_lowercase()));

        match extension {
            Some(ext) => {
                if !config.quick_scan.extensions.iter().any(|x| x.to_lowercase() == ext) {
                    return Ok(());
                }
            }
            None => return Ok(()),
        }
    }

    if path.is_dir() {
        let entries = fs::read_dir(path)
            .map_err(|_| format!("No es pot llegir el directori: {}", path.to_string_lossy()))?;

        for entry in entries {
            let entry = entry.map_err(|_| "Error llegint entrada del directori".to_string())?;
            collect_files(&entry.path(), files, config, options)?;
        }
    }

    Ok(())
}

fn scan_single_file(
    path: &Path,
    signatures_map: &SignaturesMap,
    yara_engine: &YaraEngine,
    config: &AppConfig,
) -> Result<FileScanResult, String> {
    let mut detections = Vec::new();
    let path_str = path.to_string_lossy().to_string();

    if let Some(signature) = signatures::check_file_signature(&path_str, signatures_map)? {
        detections.push(Detection {
            path: path_str.clone(),
            engine: "hash".to_string(),
            name: signature.name,
            category: "known_malware".to_string(),
            severity: signature.severity,
            confidence: signature.confidence,
            source: signature.source,
        });
    }

    let metadata = fs::metadata(path)
        .map_err(|e| format!("No es pot llegir metadata del fitxer: {}", e))?;

    let max_size_bytes = if config.max_yara_file_size_mb == 0 {
        u64::MAX
    } else {
        config.max_yara_file_size_mb * 1024 * 1024
    };

    if metadata.len() <= max_size_bytes {
        let yara_detections = yara_engine.scan_file(&path_str)?;

        for detection in yara_detections {
            detections.push(detection);
        }
    }

    let heuristic_detections = heuristics::analyze_file(path, config)?;

    for detection in heuristic_detections {
        detections.push(detection);
    }

    let pe_detections = pe_analysis::analyze_pe(path, config)?;

    for detection in pe_detections {
        detections.push(detection);
    }

    let detections = deduplicate_detections(detections);

    let decision = decision_engine::classify(&detections);

    Ok(FileScanResult {
        path: path_str,
        detections,
        final_score: decision.score,
        classification: decision.classification,
    })
}

fn deduplicate_detections(detections: Vec<Detection>) -> Vec<Detection> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();

    for detection in detections {
        let key = format!(
            "{}:{}:{}",
            detection.path, detection.engine, detection.name
        );

        if seen.insert(key) {
            result.push(detection);
        }
    }

    result
}

fn classify_global(score: i32) -> &'static str {
    if score >= 80 {
        "malware"
    } else if score >= 50 {
        "suspicious"
    } else {
        "clean"
    }
}

fn is_excluded(path: &Path, config: &AppConfig) -> bool {
    let path_str = path.to_string_lossy().replace("\\", "/").to_lowercase();

    for excluded_path in &config.exclusions.paths {
        let excluded = excluded_path.replace("\\", "/").to_lowercase();

        if path_str.starts_with(&excluded) {
            return true;
        }
    }

    if let Some(extension) = path.extension().and_then(|e| e.to_str()) {
        let ext = format!(".{}", extension.to_lowercase());

        for excluded_ext in &config.exclusions.extensions {
            if ext == excluded_ext.to_lowercase() {
                return true;
            }
        }
    }

    false
}


fn should_auto_quarantine(classification: &str, minimum: &str) -> bool {
    let classification_score = classification_level(classification);
    let minimum_score = classification_level(minimum);

    classification_score >= minimum_score
}

fn classification_level(value: &str) -> i32 {
    match value {
        "clean" => 0,
        "suspicious" => 1,
        "malware" => 2,
        "quarantined" => 3,
        _ => 0,
    }
}


#[derive(Clone)]
pub struct ScanOptions {
    pub quick_scan: bool,
}


pub fn quick_scan_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Ok(user_profile) = std::env::var("USERPROFILE") {
        let critical_paths = vec![
            "Desktop",
            "Downloads",
            "AppData/Local/Temp",
            "AppData/Roaming",
        ];

        for relative in critical_paths {
            paths.push(PathBuf::from(&user_profile).join(relative));
        }
    }

    paths
}


pub fn quick_scan(
    signatures_map: &SignaturesMap,
    yara_engine: &YaraEngine,
    config: &AppConfig,
) -> Result<ScanResult, String> {
    let options = ScanOptions {
        quick_scan: true,
    };

    let quick_paths = quick_scan_paths();

    let mut all_files = Vec::new();

    for path in quick_paths {
        if path.exists() {
            collect_files(&path, &mut all_files, config, &options)?;
        }
    }

    scan_files(
        all_files,
        signatures_map,
        yara_engine,
        config,
    )
}