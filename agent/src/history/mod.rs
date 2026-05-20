use std::fs;
use std::path::Path;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const HISTORY_DIR: &str = "../history";
const HISTORY_FILE: &str = "../history/history.json";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HistoryEntry {
    pub id: String,
    pub timestamp: String,
    pub action: String,
    pub path: Option<String>,
    pub result: String,
    pub score: Option<i32>,
    pub details: String,
}

pub fn add_history_entry(
    action: &str,
    path: Option<String>,
    result: &str,
    score: Option<i32>,
    details: &str,
) -> Result<HistoryEntry, String> {
    fs::create_dir_all(HISTORY_DIR)
        .map_err(|e| format!("No es pot crear la carpeta history: {}", e))?;

    let entry = HistoryEntry {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now().to_rfc3339(),
        action: action.to_string(),
        path,
        result: result.to_string(),
        score,
        details: details.to_string(),
    };

    let mut entries = load_history();
    entries.push(entry.clone());

    save_history(&entries)?;

    Ok(entry)
}

pub fn list_history() -> Result<Vec<HistoryEntry>, String> {
    let mut entries = load_history();

    entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    Ok(entries)
}

fn load_history() -> Vec<HistoryEntry> {
    let path = Path::new(HISTORY_FILE);

    if !path.exists() {
        return Vec::new();
    }

    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(_) => return Vec::new(),
    };

    serde_json::from_str(&content).unwrap_or_else(|_| Vec::new())
}

fn save_history(entries: &[HistoryEntry]) -> Result<(), String> {
    fs::create_dir_all(HISTORY_DIR)
        .map_err(|e| format!("No es pot crear history: {}", e))?;

    let json = serde_json::to_string_pretty(entries)
        .map_err(|e| format!("Error serialitzant historial: {}", e))?;

    fs::write(HISTORY_FILE, json)
        .map_err(|e| format!("Error guardant history.json: {}", e))
}