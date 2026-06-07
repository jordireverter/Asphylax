use std::fs::{self, File};
use std::io::{Read, Write, BufReader, BufWriter};
use std::path::Path;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::paths;

// Màscara de xifratge/ofuscació simètrica (estàndard industrial per immobilitzar malware)
const XOR_KEY: u8 = 0x5A; 
const BUFFER_SIZE: usize = 8192; // 8KB per a transferència eficient sense col·lapsar la RAM

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: String,
    pub quarantine_path: String,
    pub filename: String,
    pub quarantined_at: String,
    pub status: String,
}

/// NOVA FUNCIÓ AUXILIAR: Copia un fitxer a un altre destí mentre n'ofusca o en desofusca els bytes mitjançant XOR.
/// Això immobilitza completament el programari maliciós i evita que es pugui executar accidentalment.
fn copy_with_xor(source: &Path, destination: &Path) -> Result<(), String> {
    let src_file = File::open(source)
        .map_err(|e| format!("Error obrint fitxer d'origen per XOR: {}", e))?;
    let mut reader = BufReader::new(src_file);

    let dest_file = File::create(destination)
        .map_err(|e| format!("Error creant fitxer de destí per XOR: {}", e))?;
    let mut writer = BufWriter::new(dest_file);

    let mut buffer = [0u8; BUFFER_SIZE];

    loop {
        let bytes_read = reader.read(&mut buffer)
            .map_err(|e| format!("Error llegint bloc per XOR: {}", e))?;
        
        if bytes_read == 0 {
            break;
        }

        // Apliquem l'operació XOR bit a bit a cadascun dels bytes del bloc actual
        for byte in &mut buffer[..bytes_read] {
            *byte ^= XOR_KEY;
        }

        writer.write_all(&buffer[..bytes_read])
            .map_err(|e| format!("Error escrivint bloc transformat amb XOR: {}", e))?;
    }

    writer.flush().map_err(|e| format!("Error forçant escriptura al disc: {}", e))?;
    Ok(())
}

pub fn quarantine_file(path_str: &str) -> Result<QuarantineEntry, String> {
    let original_path = Path::new(path_str);

    if !original_path.exists() {
        return Err("El fitxer no existeix".to_string());
    }

    if !original_path.is_file() {
        return Err("Només es poden posar fitxers en quarantena".to_string());
    }

    let quarantine_dir = paths::quarantine_dir();
    fs::create_dir_all(&quarantine_dir)
        .map_err(|e| format!("No es pot crear la carpeta quarantine: {}", e))?;

    let filename = original_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown")
        .to_string();

    let id = Uuid::new_v4().to_string();

    let quarantine_filename = format!("{}_{}", id, filename);
    let quarantine_path = quarantine_dir.join(quarantine_filename);

    // MODIFICACIÓ CRÍTICA: En lloc de fer un rename pur, processem els bytes mitjançant XOR cap al directori segur
    copy_with_xor(original_path, &quarantine_path)?;

    // Una vegada escrit el fitxer d'ofuscació inert de forma segura, eliminem el fitxer perillós original
    fs::remove_file(original_path)
        .map_err(|e| format!("Error eliminant el fitxer original perillós del sistema: {}", e))?;

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
    let content = match fs::read_to_string(paths::quarantine_index_file()) {
        Ok(content) => content,
        Err(_) => return Vec::new(),
    };

    serde_json::from_str(&content).unwrap_or_else(|_| Vec::new())
}

fn save_entries(entries: &[QuarantineEntry]) -> Result<(), String> {
    fs::create_dir_all(paths::quarantine_dir())
        .map_err(|e| format!("No es pot crear quarantine: {}", e))?;

    let json = serde_json::to_string_pretty(entries)
        .map_err(|e| format!("Error serialitzant quarantena: {}", e))?;

    fs::write(paths::quarantine_index_file(), json)
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

    // MODIFICACIÓ CRÍTICA: Fem l'operació inversa del XOR per tornar a reconstruir l'estructura original del fitxer
    copy_with_xor(quarantine_path, original_path)?;

    // Una vegada restaurat el binari original per desig de l'usuari, esborrem l'arxiu d'evidència de la quarantena
    fs::remove_file(quarantine_path)
        .map_err(|e| format!("Error netejant la quarantena en restaurar: {}", e))?;

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
