use std::fs;
use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::models::MalwareSignature;

const SIGNATURES_FILE: &str = "../data/signatures.json";

pub fn check_file_signature(path_str: &str) -> Result<Option<String>, String> {
    let path = Path::new(path_str);

    if !path.exists() {
        return Err("El fitxer no existeix".to_string());
    }

    if !path.is_file() {
        return Err("El path indicat no és un fitxer".to_string());
    }

    let file_hash = calculate_sha256(path)?;
    let signatures = load_signatures()?;

    for signature in signatures {
        if signature.hash_type.to_lowercase() == "sha256"
            && signature.hash_value.to_lowercase() == file_hash
        {
            return Ok(Some(signature.name));
        }
    }

    Ok(None)
}

fn load_signatures() -> Result<Vec<MalwareSignature>, String> {
    let content = fs::read_to_string(SIGNATURES_FILE)
        .map_err(|_| "No s'ha pogut llegir el fitxer de signatures".to_string())?;

    serde_json::from_str(&content)
        .map_err(|_| "El fitxer de signatures no és un JSON vàlid".to_string())
}

fn calculate_sha256(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path)
        .map_err(|_| "No s'ha pogut obrir el fitxer".to_string())?;

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .map_err(|_| "No s'ha pogut llegir el fitxer".to_string())?;

    let mut hasher = Sha256::new();
    hasher.update(&buffer);

    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}