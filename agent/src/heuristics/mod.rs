use std::fs;
use std::path::Path;

use crate::models::Detection;
use crate::models::AppConfig;

const BASE64_MIN_LENGTH: usize = 40;
const ENTROPY_THRESHOLD: f64 = 7.5;

pub fn analyze_file(path: &Path, config: &AppConfig) -> Result<Vec<Detection>, String> {
    if !config.heuristics.enabled {
        return Ok(Vec::new());
    }
    let mut detections = Vec::new();
    let path_str = path.to_string_lossy().to_string();

    let mut has_double_ext = false;
    let mut has_entropy = false;
    let mut has_base64 = false;
    let mut has_url = false;

    if let Some(file_name) = path.file_name().and_then(|f| f.to_str()) {
        if has_double_extension(file_name) {
            has_double_ext = true;
            detections.push(build_detection(
                &path_str,
                "Double extension",
                "suspicious_filename",
                40,
                "medium",
            ));
        }
    }

    let content = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(detections),
    };

    let entropy = calculate_entropy(&content);
    if entropy > config.heuristics.entropy_threshold {
        has_entropy = true;
        detections.push(build_detection(
            &path_str,
            "High entropy",
            "obfuscation",
            40,
            "medium",
        ));
    }

    let text = String::from_utf8_lossy(&content).to_string();

    if has_long_base64(&text, config.heuristics.base64_min_length) {
        has_base64 = true;
        detections.push(build_detection(
            &path_str,
            "Long Base64 string",
            "encoded_payload",
            40,
            "medium",
        ));
    }

    if has_suspicious_url(&text) {
        has_url = true;
        detections.push(build_detection(
            &path_str,
            "Suspicious URL",
            "network_indicator",
            30,
            "low",
        ));
    }

    // 🔹 PowerShell encoded
    if has_powershell_encoded(&text) {
        detections.push(build_detection(
            &path_str,
            "PowerShell EncodedCommand",
            "powershell_execution",
            config.heuristics.confidence.powershell_encoded,
            "high",
        ));
    }

    // 🔹 Suspicious commands
    if has_suspicious_commands(&text) {
        detections.push(build_detection(
            &path_str,
            "Suspicious command execution",
            "command_execution",
            config.heuristics.confidence.suspicious_command,
            "medium",
        ));
    }

    // 🔹 Download + execute
    if has_download_execute_pattern(&text) {
        detections.push(build_detection(
            &path_str,
            "Download and execute pattern",
            "remote_execution",
            config.heuristics.confidence.download_execute,
            "high",
        ));
    }

    if has_base64 && has_url {
        detections.push(build_detection(
            &path_str,
            "Encoded content with network indicator",
            "medium_risk_combination",
            60,
            "high",
        ));
    }

    if has_double_ext && has_url {
        detections.push(build_detection(
            &path_str,
            "Disguised executable with network indicator",
            "high_risk_combination",
            70,
            "high",
        ));
    }

    if has_entropy && has_base64 && has_url {
        detections.push(build_detection(
            &path_str,
            "Obfuscated payload with network activity",
            "high_risk_combination",
            70,
            "high",
        ));
    }

    Ok(group_heuristic_detections(&path_str, detections))
}

fn build_detection(
    path: &str,
    name: &str,
    category: &str,
    confidence: i32,
    severity: &str,
) -> Detection {
    Detection {
        path: path.to_string(),
        engine: "heuristic".to_string(),
        name: name.to_string(),
        category: category.to_string(),
        severity: severity.to_string(),
        confidence,
        source: "heuristic_engine".to_string(),
    }
}

fn has_double_extension(file_name: &str) -> bool {
    let parts: Vec<&str> = file_name.split('.').collect();

    if parts.len() < 3 {
        return false;
    }

    let dangerous_ext = ["exe", "scr", "bat", "cmd", "ps1", "vbs", "js"];

    if let Some(last) = parts.last() {
        return dangerous_ext.contains(&last.to_lowercase().as_str());
    }

    false
}

fn has_long_base64(text: &str, min_len: usize) -> bool {
    let mut current = 0;

    for c in text.chars() {
        if c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' {
            current += 1;

            if current >= BASE64_MIN_LENGTH {
                return true;
            }
        } else {
            current = 0;
        }
    }

    false
}

fn has_suspicious_url(text: &str) -> bool {
    let text_lower = text.to_lowercase();

    let indicators = [
        "http://",
        "https://",
        ".onion",
        "pastebin",
        "raw.githubusercontent",
        "bit.ly",
        "tinyurl",
    ];

    indicators.iter().any(|indicator| text_lower.contains(indicator))
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0usize; 256];

    for &b in data {
        freq[b as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count == 0 {
            continue;
        }

        let p = count as f64 / len;
        entropy -= p * p.log2();
    }

    entropy
}


fn group_heuristic_detections(
    path: &str,
    detections: Vec<Detection>,
) -> Vec<Detection> {
    if detections.len() < 2 {
        return detections;
    }

    let names = detections
        .iter()
        .map(|d| d.name.clone())
        .collect::<Vec<String>>()
        .join(" + ");

    let max_confidence = detections
        .iter()
        .map(|d| d.confidence)
        .max()
        .unwrap_or(0);

    let total_confidence = detections
        .iter()
        .map(|d| d.confidence)
        .sum::<i32>();

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
        engine: "heuristic".to_string(),
        name: format!("Heuristic combination: {}", names),
        category,
        severity: severity.to_string(),
        confidence: total_confidence.max(max_confidence),
        source: "heuristic_engine".to_string(),
    }]
}


fn has_powershell_encoded(text: &str) -> bool {
    let lower = text.to_lowercase();

    lower.contains("powershell")
        && (
            lower.contains("-encodedcommand")
            || lower.contains("frombase64string")
            || lower.contains("iex(")
        )
}

fn has_suspicious_commands(text: &str) -> bool {
    let lower = text.to_lowercase();

    let commands = [
        "cmd.exe",
        "powershell.exe",
        "wscript",
        "cscript",
        "mshta",
        "rundll32",
        "regsvr32",
        "bitsadmin",
        "certutil",
    ];

    commands.iter().any(|cmd| lower.contains(cmd))
}

fn has_download_execute_pattern(text: &str) -> bool {
    let lower = text.to_lowercase();

    let download_keywords = [
        "downloadstring",
        "downloadfile",
        "invoke-webrequest",
        "wget",
        "curl",
        "start-process",
        "iex",
    ];

    let has_download = download_keywords
        .iter()
        .any(|k| lower.contains(k));

    let has_url = has_suspicious_url(text);

    has_download && has_url
}