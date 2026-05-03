use std::collections::HashMap;
use std::fs;

use sha2::{Digest, Sha256};

use crate::models::{MalwareSignature, SignaturesDatabase};

const SIGNATURES_FILE: &str = "../data/signatures.json";
const TEST_SIGNATURES_FILE: &str = "../data/test_signatures.json";

pub type SignaturesMap = HashMap<String, MalwareSignature>;


fn load_signatures_file(
    path: &str,
    map: &mut SignaturesMap,
) -> Result<usize, String> {

    println!("Carregant signatures des de: {}", path);

    let content = fs::read_to_string(path)
        .map_err(|e| format!("Error llegint {}: {}", path, e))?;

    let db: SignaturesDatabase =
        serde_json::from_str(&content)
            .map_err(|e| format!("Error parsejant JSON {}: {}", path, e))?;

    let mut loaded = 0;

    for signature in db.entries {
        if signature.enabled {
            map.insert(signature.hash_value.clone(), signature);
            loaded += 1;
        }
    }

    Ok(loaded)
}


pub fn load_signatures() -> Result<SignaturesMap, String> {

    let mut map = HashMap::new();

    let real_loaded =
        load_signatures_file(SIGNATURES_FILE, &mut map)?;

    println!("Signatures reals carregades: {}", real_loaded);

    let test_loaded =
        load_signatures_file(TEST_SIGNATURES_FILE, &mut map)?;

    println!("Signatures test carregades: {}", test_loaded);

    println!("Total signatures al HashMap: {}", map.len());

    Ok(map)
}


pub fn check_hash(
    hash: &str,
    signatures: &SignaturesMap,
) -> Option<MalwareSignature> {
    signatures.get(hash).cloned()
}


pub fn calculate_sha256(path: &str) -> Result<String, String> {
    let bytes = fs::read(path)
        .map_err(|e| format!("Error llegint fitxer: {}", e))?;

    let mut hasher = Sha256::new();
    hasher.update(bytes);

    Ok(format!("{:x}", hasher.finalize()))
}



pub fn check_file_signature(
    path: &str,
    signatures: &SignaturesMap,
) -> Result<Option<MalwareSignature>, String> {
    let hash = calculate_sha256(path)?;

    match check_hash(&hash, signatures) {
        Some(signature) => Ok(Some(signature)),
        None => Ok(None),
    }
}