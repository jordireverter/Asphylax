use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct RequestMessage {
    pub action: String,
    pub path: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub scanned_files: usize,
    pub detections: Vec<String>,
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