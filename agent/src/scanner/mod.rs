use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::UNIX_EPOCH;

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::decision_engine;
use crate::heuristics;
use crate::models::{AppConfig, Detection, FileScanResult, ScanResult};
use crate::pe_analysis;
use crate::signatures::{self, SignatureDatabase};
use crate::yara_engine::YaraEngine;
use crate::quarantine;
use crate::paths;

const DEFAULT_FULL_SCAN_YARA_TIMEOUT_SECS: u64 = 60;

pub fn scan_path(
    path_str: &str,
    signature_db: &SignatureDatabase,
    yara_engine: &YaraEngine,
    config: &AppConfig,
) -> Result<ScanResult, String> {
    scan_path_with_progress(
        path_str,
        signature_db,
        yara_engine,
        config,
        |_scanned, _total| Ok(()),
    )
}

pub fn scan_path_with_progress<F>(
    path_str: &str,
    signature_db: &SignatureDatabase,
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
    let options = ScanOptions { 
        quick_scan: false, 
        pe_analysis_enabled: true 
    };
    collect_files(path, &mut files, config, &options, 0)?;

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
            let file_result = match scan_single_file(file_path, signature_db, yara_engine, config, &options) {
                Ok(result) => result,
                Err(error) => {
                    eprintln!("Saltant fitxer {}: {}", file_path.to_string_lossy(), error);
                    skipped_file_result(file_path)
                }
            };

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

fn collect_files(
    path: &Path,
    files: &mut Vec<PathBuf>,
    config: &AppConfig,
    options: &ScanOptions,
    depth: usize,
) -> Result<(), String> {

    if is_excluded(path, config) {
        return Ok(());
    }

    if path.is_file() {
        if options.quick_scan && !is_quick_scan_candidate(path, config) {
            return Ok(());
        }

        files.push(path.to_path_buf());
        return Ok(());
    }

    if path.is_dir() {
        if options.quick_scan {
            if depth > config.quick_scan.max_depth || is_quick_scan_excluded_dir(path, config) {
                return Ok(());
            }
        }

        let entries = match fs::read_dir(path) {
            Ok(entries) => entries,
            Err(error) => {
                eprintln!("Saltant directori {}: {}", path.to_string_lossy(), error);
                return Ok(());
            }
        };

        for entry in entries {
            let Ok(entry) = entry else {
                continue;
            };
            collect_files(&entry.path(), files, config, options, depth + 1)?;
        }
    }

    Ok(())
}

fn is_yara_candidate(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return true; 
    };

    let ext = ext.to_lowercase();
    let dangerous_exts = [
        "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "wsf", "js", "jse", 
        "docm", "xlsm", "pptm", "bin", "elf", "sh", "py"
    ];

    dangerous_exts.contains(&ext.as_str())
}

fn scan_single_file(
    path: &Path,
    signature_db: &SignatureDatabase,
    yara_engine: &YaraEngine,
    config: &AppConfig,
    options: &ScanOptions,
) -> Result<FileScanResult, String> {
    let mut detections = Vec::new();
    let path_str = path.to_string_lossy().to_string();

    if options.quick_scan {
        let metadata = fs::metadata(path)
            .map_err(|e| format!("No es pot llegir metadata del fitxer: {}", e))?;
        let bytes = fs::read(path)
            .map_err(|e| format!("Error llegint fitxer per quick scan: {}", e))?;

        let hash = calculate_sha256_bytes(&bytes);
        if let Some(signature) = signatures::check_hash(&hash, signature_db) {
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

        let max_yara_size = if config.max_yara_file_size_mb == 0 {
            u64::MAX
        } else {
            config.max_yara_file_size_mb * 1024 * 1024
        };

        if metadata.len() <= max_yara_size && is_yara_candidate(path) {
            match yara_engine.scan_bytes(&path_str, &bytes, config.quick_scan.yara_timeout_secs) {
                Ok(yara_detections) => detections.extend(yara_detections),
                Err(e) => {
                    eprintln!("Saltant l'escaneig YARA de {} per error/timeout: {}", path_str, e);
                }
            }
        }

        detections.extend(heuristics::analyze_bytes(path, &bytes, config)?);

        let detections = deduplicate_detections(detections);
        let decision = decision_engine::classify(&detections);

        return Ok(FileScanResult {
            path: path_str,
            detections,
            final_score: decision.score,
            classification: decision.classification,
        });
    }

    // 1. ESCANEIG DE SIGNATURES COMPLET (Filtre Bloom + Hash global)
    if let Some(signature) = signatures::check_file_signature(&path_str, signature_db)? {
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

    // 2. ESCANEIG DE SIGNATURES ANTI-PADDING (Mòdul avançat de seccions PE)
    if options.pe_analysis_enabled {
        if let Ok(section_hashes) = pe_analysis::calculate_pe_section_hashes(path) {
            for (section_name, s_hash) in section_hashes {
                if let Some(signature) = signatures::check_hash(&s_hash, signature_db) {
                    detections.push(Detection {
                        path: path_str.clone(),
                        engine: "hash_section".to_string(),
                        name: format!("{} (In Section {})", signature.name, section_name),
                        category: "known_malware".to_string(),
                        severity: signature.severity,
                        confidence: signature.confidence,
                        source: "pe_section_hash_match".to_string(),
                    });
                }
            }
        }
    }

    let metadata = fs::metadata(path)
        .map_err(|e| format!("No es pot llegir metadata del fitxer: {}", e))?;

    let max_size_bytes = if config.max_yara_file_size_mb == 0 {
        u64::MAX
    } else {
        config.max_yara_file_size_mb * 1024 * 1024
    };

    // 3. MOTOR YARA
    if metadata.len() <= max_size_bytes && is_yara_candidate(path) {
        match yara_engine.scan_file(&path_str, DEFAULT_FULL_SCAN_YARA_TIMEOUT_SECS) {
            Ok(yara_detections) => {
                for detection in yara_detections {
                    detections.push(detection);
                }
            },
            Err(e) => {
                eprintln!("⚠️ Saltant l'escaneig YARA de {} per error/timeout: {}", path_str, e);
            }
        }
    }

    // 4. HEURÍSTICA
    let heuristic_detections = heuristics::analyze_file(path, config)?;
    for detection in heuristic_detections {
        detections.push(detection);
    }

    // 5. ANÀLISI PE
    if options.pe_analysis_enabled && config.pe_analysis.enabled {
        let pe_detections = pe_analysis::analyze_pe(path, config)?;
        for detection in pe_detections {
            detections.push(detection);
        }
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
        let key = format!("{}:{}:{}", detection.path, detection.engine, detection.name);
        if seen.insert(key) {
            result.push(detection);
        }
    }
    result
}

fn classify_global(score: i32) -> &'static str {
    if score >= 80 { "malware" } else if score >= 50 { "suspicious" } else { "clean" }
}

fn skipped_file_result(path: &Path) -> FileScanResult {
    FileScanResult {
        path: path.to_string_lossy().to_string(),
        detections: Vec::new(),
        final_score: 0,
        classification: "clean".to_string(),
    }
}

fn calculate_sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
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
    classification_level(classification) >= classification_level(minimum)
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
    pub pe_analysis_enabled: bool
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct QuickScanCache {
    entries: HashMap<String, CachedScanResult>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct CachedScanResult {
    size: u64,
    modified_secs: u64,
    result: FileScanResult,
}

pub fn quick_scan_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(user_profile) = std::env::var("USERPROFILE") {
        let critical_paths = vec!["Desktop", "Downloads", "AppData/Local/Temp", "AppData/Roaming"];
        for relative in critical_paths {
            paths.push(PathBuf::from(&user_profile).join(relative));
        }
    }
    paths
}

pub fn quick_scan(
    signature_db: &SignatureDatabase,
    yara_engine: &YaraEngine,
    config: &AppConfig,
) -> Result<ScanResult, String> {
    let options = ScanOptions { quick_scan: true, pe_analysis_enabled: false };
    let quick_paths = quick_scan_paths();
    let mut all_files = Vec::new();

    for path in quick_paths {
        if path.exists() {
            collect_files(&path, &mut all_files, config, &options, 0)?;
        }
    }

    scan_files(all_files, signature_db, yara_engine, config, &options, |_scanned, _total| Ok(()))
}

fn scan_files<F>(
    files: Vec<PathBuf>,
    signature_db: &SignatureDatabase,
    yara_engine: &YaraEngine,
    config: &AppConfig,
    options: &ScanOptions,
    on_progress: F,
) -> Result<ScanResult, String>
where
    F: Fn(usize, usize) -> Result<(), String> + Sync,
{
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
    let quick_cache = if options.quick_scan {
        Some(Mutex::new(load_quick_scan_cache()))
    } else {
        None
    };

    let partial_results: Result<Vec<FileScanResult>, String> = files
        .par_iter()
        .map(|file_path| {
            let file_result = match if let Some(cache) = &quick_cache {
                scan_single_file_with_cache(file_path, signature_db, yara_engine, config, options, cache)
            } else {
                scan_single_file(file_path, signature_db, yara_engine, config, options)
            } {
                Ok(result) => result,
                Err(error) => {
                    eprintln!("Saltant fitxer {}: {}", file_path.to_string_lossy(), error);
                    skipped_file_result(file_path)
                }
            };
            let scanned = scanned_counter.fetch_add(1, Ordering::SeqCst) + 1;
            let percent = (scanned * 100) / total_files;
            let mut previous = last_percent_sent.load(Ordering::SeqCst);

            while percent > previous {
                match last_percent_sent.compare_exchange(previous, percent, Ordering::SeqCst, Ordering::SeqCst) {
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

    if let Some(cache) = quick_cache {
        if let Ok(cache) = cache.into_inner() {
            let _ = save_quick_scan_cache(&cache);
        }
    }

    file_results.retain(|file| !file.detections.is_empty());

    if config.auto_quarantine.enabled {
        for file in &mut file_results {
            if should_auto_quarantine(&file.classification, &config.auto_quarantine.minimum_classification) {
                match quarantine::quarantine_file(&file.path) {
                    Ok(_) => { file.classification = "quarantined".to_string(); }
                    Err(error) => { eprintln!("No s'ha pogut posar en quarantena {}: {}", file.path, error); }
                }
            }
        }
    }

    let total_detections = file_results.iter().map(|file| file.detections.len()).sum::<usize>();
    let final_score = file_results.iter().map(|file| file.final_score).max().unwrap_or(0);
    let classification = classify_global(final_score).to_string();

    Ok(ScanResult {
        scanned_files: total_files,
        total_detections,
        final_score,
        classification,
        files: file_results,
    })
}

fn is_quick_scan_candidate(path: &Path, config: &AppConfig) -> bool {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return false,
    };

    let max_size = config.quick_scan.max_file_size_mb * 1024 * 1024;
    if metadata.len() > max_size { return false; }

    let extension = path.extension().and_then(|ext| ext.to_str()).map(|ext| format!(".{}", ext.to_lowercase()));
    match extension {
        Some(ext) => config.quick_scan.extensions.iter().any(|allowed| allowed.to_lowercase() == ext),
        None => false,
    }
}

fn scan_single_file_with_cache(
    path: &Path,
    signature_db: &SignatureDatabase,
    yara_engine: &YaraEngine,
    config: &AppConfig,
    options: &ScanOptions,
    cache: &Mutex<QuickScanCache>,
) -> Result<FileScanResult, String> {
    let metadata = fs::metadata(path)
        .map_err(|e| format!("No es pot llegir metadata del fitxer: {}", e))?;
    let cache_key = normalize_cache_key(path);
    let modified_secs = modified_secs(&metadata);

    if let Ok(cache_guard) = cache.lock() {
        if let Some(cached) = cache_guard.entries.get(&cache_key) {
            if cached.size == metadata.len() && cached.modified_secs == modified_secs {
                return Ok(cached.result.clone());
            }
        }
    }

    let result = scan_single_file(path, signature_db, yara_engine, config, options)?;

    if let Ok(mut cache_guard) = cache.lock() {
        cache_guard.entries.insert(
            cache_key,
            CachedScanResult {
                size: metadata.len(),
                modified_secs,
                result: result.clone(),
            },
        );
    }

    Ok(result)
}

fn load_quick_scan_cache() -> QuickScanCache {
    let path = paths::data_file("quick_scan_cache.json");
    let Ok(content) = fs::read_to_string(path) else {
        return QuickScanCache::default();
    };

    serde_json::from_str(&content).unwrap_or_default()
}

fn save_quick_scan_cache(cache: &QuickScanCache) -> Result<(), String> {
    let path = paths::data_file("quick_scan_cache.json");
    let json = serde_json::to_string_pretty(cache)
        .map_err(|e| format!("Error serialitzant cache quick scan: {}", e))?;

    fs::write(path, json)
        .map_err(|e| format!("Error guardant cache quick scan: {}", e))
}

fn normalize_cache_key(path: &Path) -> String {
    path.to_string_lossy().replace("\\", "/").to_lowercase()
}

fn modified_secs(metadata: &fs::Metadata) -> u64 {
    metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn is_quick_scan_excluded_dir(path: &Path, config: &AppConfig) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };

    config
        .quick_scan
        .excluded_dirs
        .iter()
        .any(|excluded| excluded.eq_ignore_ascii_case(name))
}
