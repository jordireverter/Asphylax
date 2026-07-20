use std::fs;

use crate::models::AppConfig;
use crate::paths;

pub fn load_config() -> Result<AppConfig, String> {
    let content = fs::read_to_string(paths::data_file("config.json"))
        .map_err(|e| format!("No es pot llegir config.json: {}", e))?;

    serde_json::from_str(&content)
        .map_err(|e| format!("Error parsejant config.json: {}", e))
}

pub fn save_config(config: &AppConfig) -> Result<(), String> {
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| format!("Error serialitzant config: {}", e))?;

    fs::write(paths::data_file("config.json"), json)
        .map_err(|e| format!("No es pot guardar config.json: {}", e))
}
