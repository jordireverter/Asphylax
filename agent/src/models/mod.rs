use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct RequestMessage {
    pub action: String,
    pub path: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ResponseMessage {
    pub status: String,
    pub message: String,
    pub data: Option<String>,
}