use std::path::Path;
use sha2::{Sha256, Digest};

use pelite::FileMap;
use pelite::pe32::{Pe as Pe32, PeFile as PeFile32};
use pelite::pe64::{Pe as Pe64, PeFile as PeFile64};

use crate::models::{AppConfig, Detection};

#[derive(Default)]
struct PeIndicators {
    process_injection: Vec<String>,
    process_execution: Vec<String>,
    networking: Vec<String>,
    dynamic_api_resolution: Vec<String>,
    import_count: usize,
}

const SUSPICIOUS_PE_THRESHOLD: i32 = 50;
const MALWARE_PE_THRESHOLD: i32 = 80;
const PROCESS_INJECTION_WEIGHT: i32 = 35;
const PROCESS_EXECUTION_WEIGHT: i32 = 15;
const NETWORKING_WEIGHT: i32 = 10;
const DYNAMIC_API_RESOLUTION_WEIGHT: i32 = 55;
const LOW_IMPORT_DYNAMIC_API_BONUS: i32 = 25;

/// NOVA FUNCIÓ PROFESSIONAL: Calcula el hash SHA-256 independent de cadascuna de les seccions del PE.
/// Permet detectar codi maliciós encara que l'atacant hagi aplicat 'Padding' o tècniques d'evasió global.
pub fn calculate_pe_section_hashes(path: &Path) -> Result<Vec<(String, String)>, String> {
    let file_map = FileMap::open(path).map_err(|e| format!("Error obrint FileMap: {}", e))?;
    let mut section_hashes = Vec::new();

    if let Ok(pe_file) = PeFile64::from_bytes(&file_map) {
        let section_headers = pe_file.section_headers();
        for section in section_headers {
            let name = section.name().unwrap_or("unknown").to_string();
            if let Ok(section_data) = pe_file.get_section_bytes(section) {
                let mut hasher = Sha256::new();
                hasher.update(section_data);
                section_hashes.push((name, format!("{:x}", hasher.finalize())));
            }
        }
    } else if let Ok(pe_file) = PeFile32::from_bytes(&file_map) {
        let section_headers = pe_file.section_headers();
        for section in section_headers {
            let name = section.name().unwrap_or("unknown").to_string();
            if let Ok(section_data) = pe_file.get_section_bytes(section) {
                let mut hasher = Sha256::new();
                hasher.update(section_data);
                section_hashes.push((name, format!("{:x}", hasher.finalize())));
            }
        }
    }

    Ok(section_hashes)
}

pub fn analyze_pe(
    path: &Path,
    config: &AppConfig,
) -> Result<Vec<Detection>, String> {
    let mut detections = Vec::new();

    if !config.pe_analysis.enabled {
        return Ok(detections);
    }

    if !is_pe_candidate(path) {
        return Ok(detections);
    }

    let path_str = path.to_string_lossy().to_string();

    let file_map = match FileMap::open(path) {
        Ok(file) => file,
        Err(_) => return Ok(detections),
    };

    let mut indicators = PeIndicators::default();

    if let Ok(pe_file) = PeFile64::from_bytes(&file_map) {
        analyze_imports_64(&pe_file, &mut indicators)?;
    } else if let Ok(pe_file) = PeFile32::from_bytes(&file_map) {
        analyze_imports_32(&pe_file, &mut indicators)?;
    } else {
        return Ok(detections);
    }

    analyze_pe_strings(file_map.as_ref(), &mut indicators);

    if let Some(detection) = build_weighted_pe_detection(&path_str, &indicators, config) {
        detections.push(detection);
    }

    Ok(detections)
}

fn is_pe_candidate(path: &Path) -> bool {
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let pe_extensions = ["exe", "dll", "scr", "sys"];

    pe_extensions.contains(&extension.as_str())
}

fn analyze_imports_64(
    pe_file: &PeFile64,
    indicators: &mut PeIndicators,
) -> Result<(), String> {
    let imports = match pe_file.imports() {
        Ok(imports) => imports,
        Err(_) => return Ok(()),
    };

    for dll in imports {
        let int = match dll.int() {
            Ok(int) => int,
            Err(_) => continue,
        };

        for import in int {
            let import_name = match import {
                Ok(import) => format!("{:?}", import),
                Err(_) => continue,
            };

            indicators.import_count += 1;
            classify_indicator(&import_name, indicators);
        }
    }

    Ok(())
}

fn analyze_imports_32(
    pe_file: &PeFile32,
    indicators: &mut PeIndicators,
) -> Result<(), String> {
    let imports = match pe_file.imports() {
        Ok(imports) => imports,
        Err(_) => return Ok(()),
    };

    for dll in imports {
        let int = match dll.int() {
            Ok(int) => int,
            Err(_) => continue,
        };

        for import in int {
            let import_name = match import {
                Ok(import) => format!("{:?}", import),
                Err(_) => continue,
            };

            indicators.import_count += 1;
            classify_indicator(&import_name, indicators);
        }
    }

    Ok(())
}

fn analyze_pe_strings(bytes: &[u8], indicators: &mut PeIndicators) {
    let content = String::from_utf8_lossy(bytes);
    classify_indicator(&content, indicators);
}

fn classify_indicator(text: &str, indicators: &mut PeIndicators) {
    let process_injection_indicators = [
        "VirtualAlloc",
        "VirtualProtect",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "CreateRemoteThread",
        "NtWriteVirtualMemory",
        "NtCreateThreadEx",
    ];

    let process_access_indicators = [
        "OpenProcess",
    ];

    let process_execution_indicators = [
        "WinExec",
        "ShellExecuteA",
        "ShellExecuteW",
        "CreateProcessA",
        "CreateProcessW",
    ];

    let networking_indicators = [
        "URLDownloadToFileA",
        "URLDownloadToFileW",
        "InternetOpenUrlA",
        "InternetOpenUrlW",
        "InternetConnectA",
        "InternetConnectW",
        "WSAStartup",
        "connect",
        "send",
        "recv",
        "socket",
    ];

    let dynamic_api_indicators = [
        "LoadLibraryA",
        "LoadLibraryW",
        "LoadLibraryExA",
        "LoadLibraryExW",
        "GetProcAddress",
        "LdrLoadDll",
        "LdrGetProcedureAddress",
    ];

    for indicator in process_injection_indicators {
        if text.contains(indicator) {
            push_unique(&mut indicators.process_injection, indicator);
        }
    }

    for indicator in process_access_indicators {
        if text.contains(indicator) {
            push_unique(&mut indicators.process_execution, indicator);
        }
    }

    for indicator in process_execution_indicators {
        if text.contains(indicator) {
            push_unique(&mut indicators.process_execution, indicator);
        }
    }

    for indicator in networking_indicators {
        if text.contains(indicator) {
            push_unique(&mut indicators.networking, indicator);
        }
    }

    for indicator in dynamic_api_indicators {
        if text.contains(indicator) {
            push_unique(&mut indicators.dynamic_api_resolution, indicator);
        }
    }
}

fn push_unique(list: &mut Vec<String>, value: &str) {
    if !list.iter().any(|item| item == value) {
        list.push(value.to_string());
    }
}

fn build_weighted_pe_detection(
    path: &str,
    indicators: &PeIndicators,
    config: &AppConfig,
) -> Option<Detection> {
    let mut score = 0;
    let mut names = Vec::new();
    let mut categories = Vec::new();

    if !indicators.process_injection.is_empty() {
        score += PROCESS_INJECTION_WEIGHT;
        names.push(format!("process injection: {}", indicators.process_injection.join(", ")));
        categories.push("process_injection");
    }

    if !indicators.process_execution.is_empty() {
        score += PROCESS_EXECUTION_WEIGHT;
        names.push(format!("process execution: {}", indicators.process_execution.join(", ")));
        categories.push("process_execution");
    }

    if !indicators.networking.is_empty() {
        score += NETWORKING_WEIGHT;
        names.push(format!("networking: {}", indicators.networking.join(", ")));
        categories.push("networking");
    }

    let has_loader = indicators.dynamic_api_resolution.iter().any(|name| {
        matches!(
            name.as_str(),
            "LoadLibraryA" | "LoadLibraryW" | "LoadLibraryExA" | "LoadLibraryExW" | "LdrLoadDll"
        )
    });
    let has_resolver = indicators.dynamic_api_resolution.iter().any(|name| {
        matches!(name.as_str(), "GetProcAddress" | "LdrGetProcedureAddress")
    });

    if has_loader && has_resolver {
        score += DYNAMIC_API_RESOLUTION_WEIGHT;
        if indicators.import_count <= 3 {
            score += LOW_IMPORT_DYNAMIC_API_BONUS;
        }
        names.push(format!(
            "dynamic API resolution: {}",
            indicators.dynamic_api_resolution.join(", ")
        ));
        categories.push("dynamic_api_resolution");
    }

    if score < SUSPICIOUS_PE_THRESHOLD {
        return None;
    }

    let confidence = score.min(100);
    let severity = if score >= MALWARE_PE_THRESHOLD { "high" } else { "medium" };
    let configured_floor = if score >= MALWARE_PE_THRESHOLD {
        config.pe_analysis.confidence.process_injection
    } else {
        config.pe_analysis.confidence.suspicious_import
    };

    Some(Detection {
        path: path.to_string(),
        engine: "pe_analysis".to_string(),
        name: format!("PE weighted score {}: {}", score, names.join(" + ")),
        category: categories.join("+"),
        severity: severity.to_string(),
        confidence: confidence.max(configured_floor),
        source: "pe_static_analysis".to_string(),
    })
}
