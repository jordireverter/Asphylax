use std::fs;

use crate::models::AppConfig;

const CONFIG_FILE: &str = "../data/config.json";

pub fn load_config() -> Result<AppConfig, String> {
    let content = fs::read_to_string(CONFIG_FILE)
        .map_err(|e| format!("Error llegint config.json: {}", e))?;

    serde_json::from_str(&content)
        .map_err(|e| format!("Error parsejant config.json: {}", e))
}