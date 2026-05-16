use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct RequestMessage {
    pub action: String,
    pub path: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct Detection {
    pub path: String,
    pub engine: String,
    pub name: String,
    pub category: String,
    pub severity: String,
    pub confidence: i32,
    pub source: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct FileScanResult {
    pub path: String,
    pub detections: Vec<Detection>,
    pub final_score: i32,
    pub classification: String,
}

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub scanned_files: usize,
    pub total_detections: usize,
    pub final_score: i32,
    pub classification: String,
    pub files: Vec<FileScanResult>,
}


#[derive(Debug, Serialize)]
pub struct ResponseMessage {
    pub status: String,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MalwareSignature {
    pub id: String,
    pub name: String,
    pub family: Option<String>,
    pub hash_type: String,
    pub hash_value: String,
    pub severity: String,
    pub confidence: i32,
    pub tags: Vec<String>,
    pub source: String,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub reference: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct SignaturesDatabase {
    pub version: i32,
    pub entries: Vec<MalwareSignature>,
}


#[derive(Debug, Deserialize, Clone)]
pub struct PartialSignature {
    pub id: String,
    pub name: String,
    pub pattern_type: String,
    pub pattern: String,
    pub severity: String,
    pub confidence: i32,
    pub case_sensitive: Option<bool>,
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct PartialSignaturesDatabase {
    pub version: i32,
    pub entries: Vec<PartialSignature>,
}


#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub max_yara_file_size_mb: u64,
    pub heuristics: HeuristicsConfig,
    pub pe_analysis: PeAnalysisConfig,
}


#[derive(Debug, Deserialize, Clone)]
pub struct HeuristicsConfig {
    pub enabled: bool,
    pub base64_min_length: usize,
    pub entropy_threshold: f64,
    pub confidence: HeuristicsConfidence,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HeuristicsConfidence {
    pub double_extension: i32,
    pub base64: i32,
    pub url: i32,
    pub combination: i32,
    pub high_combination: i32,
    pub powershell_encoded: i32,
    pub suspicious_command: i32,
    pub download_execute: i32,
}


#[derive(Debug, Deserialize, Clone)]
pub struct PeAnalysisConfig {
    pub enabled: bool,
    pub confidence: PeConfidenceConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PeConfidenceConfig {
    pub suspicious_import: i32,
    pub process_injection: i32,
    pub networking: i32,
    pub packer: i32,
}

