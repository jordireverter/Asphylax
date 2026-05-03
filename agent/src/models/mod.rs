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

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub scanned_files: usize,
    pub detections: Vec<Detection>,
}

#[derive(Debug, Serialize)]
pub struct ResponseMessage {
    pub status: String,
    pub message: String,
    pub data: Option<ScanResult>,
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
}