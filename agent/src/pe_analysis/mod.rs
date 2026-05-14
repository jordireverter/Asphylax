use std::path::Path;

use pelite::FileMap;
use pelite::pe32::{Pe as Pe32, PeFile as PeFile32};
use pelite::pe64::{Pe as Pe64, PeFile as PeFile64};

use crate::models::{AppConfig, Detection};

#[derive(Default)]
struct PeIndicators {
    process_injection: Vec<String>,
    process_execution: Vec<String>,
    networking: Vec<String>,
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

    if !indicators.process_injection.is_empty() {
        detections.push(build_detection(
            &path_str,
            &format!(
                "PE process injection indicators: {}",
                indicators.process_injection.join(", ")
            ),
            "process_injection",
            "high",
            config.pe_analysis.confidence.process_injection,
        ));
    }

    if !indicators.process_execution.is_empty() {
        detections.push(build_detection(
            &path_str,
            &format!(
                "PE process execution indicators: {}",
                indicators.process_execution.join(", ")
            ),
            "process_execution",
            "medium",
            config.pe_analysis.confidence.suspicious_import,
        ));
    }

    if !indicators.networking.is_empty() {
        detections.push(build_detection(
            &path_str,
            &format!(
                "PE networking indicators: {}",
                indicators.networking.join(", ")
            ),
            "networking",
            "low",
            config.pe_analysis.confidence.networking,
        ));
    }

    Ok(group_pe_detections(&path_str, detections))
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
}

fn push_unique(list: &mut Vec<String>, value: &str) {
    if !list.iter().any(|item| item == value) {
        list.push(value.to_string());
    }
}

fn build_detection(
    path: &str,
    name: &str,
    category: &str,
    severity: &str,
    confidence: i32,
) -> Detection {
    Detection {
        path: path.to_string(),
        engine: "pe_analysis".to_string(),
        name: name.to_string(),
        category: category.to_string(),
        severity: severity.to_string(),
        confidence,
        source: "pe_static_analysis".to_string(),
    }
}

fn group_pe_detections(path: &str, detections: Vec<Detection>) -> Vec<Detection> {
    if detections.len() < 2 {
        return detections;
    }

    let names = detections
        .iter()
        .map(|d| d.name.clone())
        .collect::<Vec<String>>()
        .join(" + ");

    let total_confidence = detections.iter().map(|d| d.confidence).sum::<i32>();

    let severity = if detections.iter().any(|d| d.severity == "high") {
        "high"
    } else if detections.iter().any(|d| d.severity == "medium") {
        "medium"
    } else {
        "low"
    };

    let category = detections
        .iter()
        .map(|d| d.category.clone())
        .collect::<Vec<String>>()
        .join("+");

    vec![Detection {
        path: path.to_string(),
        engine: "pe_analysis".to_string(),
        name: format!("PE indicators: {}", names),
        category,
        severity: severity.to_string(),
        confidence: total_confidence,
        source: "pe_static_analysis".to_string(),
    }]
}