use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const QUARANTINE_DIR: &str = "../quarantine";
const QUARANTINE_INDEX: &str = "../quarantine/quarantine_index.json";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: String,
    pub quarantine_path: String,
    pub filename: String,
    pub quarantined_at: String,
    pub status: String,
}

pub fn quarantine_file(path_str: &str) -> Result<QuarantineEntry, String> {
    let original_path = Path::new(path_str);

    if !original_path.exists() {
        return Err("El fitxer no existeix".to_string());
    }

    if !original_path.is_file() {
        return Err("Només es poden posar fitxers en quarantena".to_string());
    }

    fs::create_dir_all(QUARANTINE_DIR)
        .map_err(|e| format!("No es pot crear la carpeta quarantine: {}", e))?;

    let filename = original_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown")
        .to_string();

    let id = Uuid::new_v4().to_string();

    let quarantine_filename = format!("{}_{}", id, filename);
    let quarantine_path = PathBuf::from(QUARANTINE_DIR).join(quarantine_filename);

    fs::rename(original_path, &quarantine_path)
        .map_err(|e| format!("Error movent fitxer a quarantena: {}", e))?;

    let entry = QuarantineEntry {
        id,
        original_path: path_str.to_string(),
        quarantine_path: quarantine_path.to_string_lossy().to_string(),
        filename,
        quarantined_at: Utc::now().to_rfc3339(),
        status: "quarantined".to_string(),
    };

    let mut entries = load_entries();
    entries.push(entry.clone());
    save_entries(&entries)?;

    Ok(entry)
}

fn load_entries() -> Vec<QuarantineEntry> {
    let content = match fs::read_to_string(QUARANTINE_INDEX) {
        Ok(content) => content,
        Err(_) => return Vec::new(),
    };

    serde_json::from_str(&content).unwrap_or_else(|_| Vec::new())
}

fn save_entries(entries: &[QuarantineEntry]) -> Result<(), String> {
    fs::create_dir_all(QUARANTINE_DIR)
        .map_err(|e| format!("No es pot crear quarantine: {}", e))?;

    let json = serde_json::to_string_pretty(entries)
        .map_err(|e| format!("Error serialitzant quarantena: {}", e))?;

    fs::write(QUARANTINE_INDEX, json)
        .map_err(|e| format!("Error guardant quarantine_index.json: {}", e))
}


pub fn list_quarantine() -> Result<Vec<QuarantineEntry>, String> {
    let mut entries = load_entries();

    entries.sort_by(|a, b| {
        b.quarantined_at.cmp(&a.quarantined_at)
    });

    Ok(entries)
}


pub fn restore_quarantine(id: &str) -> Result<QuarantineEntry, String> {
    let mut entries = load_entries();

    let entry_position = entries
        .iter()
        .position(|entry| entry.id == id)
        .ok_or_else(|| "No s'ha trobat cap entrada amb aquest ID".to_string())?;

    let mut entry = entries[entry_position].clone();

    if entry.status != "quarantined" {
        return Err("Aquest fitxer no està en estat quarantined".to_string());
    }

    let quarantine_path = Path::new(&entry.quarantine_path);
    let original_path = Path::new(&entry.original_path);

    if !quarantine_path.exists() {
        return Err("El fitxer de quarantena no existeix".to_string());
    }

    if original_path.exists() {
        return Err("Ja existeix un fitxer a la ruta original. No es restaurarà per seguretat.".to_string());
    }

    if let Some(parent) = original_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("No es pot recrear la carpeta original: {}", e))?;
    }

    fs::rename(quarantine_path, original_path)
        .map_err(|e| format!("Error restaurant el fitxer: {}", e))?;

    entry.status = "restored".to_string();

    entries[entry_position] = entry.clone();
    save_entries(&entries)?;

    Ok(entry)
}



pub fn delete_quarantine(id: &str) -> Result<QuarantineEntry, String> {
    let mut entries = load_entries();

    let entry_position = entries
        .iter()
        .position(|entry| entry.id == id)
        .ok_or_else(|| "No s'ha trobat cap entrada amb aquest ID".to_string())?;

    let mut entry = entries[entry_position].clone();

    if entry.status == "deleted" {
        return Err("Aquest fitxer ja està eliminat definitivament".to_string());
    }

    if entry.status == "restored" {
        return Err("Aquest fitxer ja ha estat restaurat i no es pot eliminar des de quarantena".to_string());
    }

    let quarantine_path = Path::new(&entry.quarantine_path);

    if quarantine_path.exists() {
        fs::remove_file(quarantine_path)
            .map_err(|e| format!("Error eliminant fitxer de quarantena: {}", e))?;
    }

    entry.status = "deleted".to_string();

    entries[entry_position] = entry.clone();
    save_entries(&entries)?;

    Ok(entry)
}