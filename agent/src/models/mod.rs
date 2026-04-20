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

#[derive(Debug, Deserialize)]
pub struct MalwareSignature {
    pub name: String,
    pub hash_type: String,
    pub hash_value: String,
}