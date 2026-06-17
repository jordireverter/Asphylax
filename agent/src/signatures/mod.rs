use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, BufReader};
use std::path::Path;
use sha2::{Digest, Sha256};
use bloomfilter::Bloom;

use crate::models::{MalwareSignature, SignaturesDatabase};
use crate::paths;

pub type SignaturesMap = HashMap<String, MalwareSignature>;

pub struct SignatureDatabase {
    pub bloom_filter: Bloom<String>,
    pub signatures_map: SignaturesMap,
}

fn load_signatures_file(
    path: &Path,
    map: &mut SignaturesMap,
    hash_list: &mut Vec<String>,
) -> Result<usize, String> {
    if !path.exists() {
        println!("[!] Fitxer de signatures no trobat: {} (s'arrencarà amb base buida)", path.display());
        return Ok(0);
    }

    println!("Carregant signatures des de: {}", path.display());

    let content = fs::read_to_string(path)
        .map_err(|e| format!("Error llegint {}: {}", path.display(), e))?;

    let db: SignaturesDatabase = serde_json::from_str(&content)
        .map_err(|e| format!("Error parsejant JSON {}: {}", path.display(), e))?;

    let mut loaded = 0;

    for signature in db.entries {
        if signature.enabled {
            let hash_lower = signature.hash_value.clone().to_lowercase();
            map.insert(hash_lower.clone(), signature);
            hash_list.push(hash_lower);
            loaded += 1;
        }
    }

    Ok(loaded)
}

pub fn load_signatures() -> Result<SignatureDatabase, String> {
    let mut map = HashMap::new();
    let mut hash_list = Vec::new();

    // 1. Càrrega JSON a RAM
    let _real_loaded = load_signatures_file(&paths::data_file("signatures.json"), &mut map, &mut hash_list)?;
    let _test_loaded = load_signatures_file(&paths::data_file("test_signatures.json"), &mut map, &mut hash_list)?;

    // 2. Construïm el filtre Bloom al vol (instantani)
    let bloom_filter = build_new_bloom(&hash_list);

    Ok(SignatureDatabase {
        bloom_filter,
        signatures_map: map,
    })
}

pub fn check_hash(
    hash: &str,
    signature_db: &SignatureDatabase,
) -> Option<MalwareSignature> {
    let hash_lower = hash.to_lowercase();
    
    if !signature_db.bloom_filter.check(&hash_lower) {
        return None;
    }
    
    signature_db.signatures_map.get(&hash_lower).cloned()
}

pub fn calculate_sha256(path: &str) -> Result<String, String> {
    let file = File::open(path).map_err(|e| format!("Error obrint fitxer pel hash: {}", e))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];

    loop {
        let count = reader.read(&mut buffer).map_err(|e| format!("Error llegint bloc: {}", e))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

pub fn check_file_signature(
    path: &str,
    signature_db: &SignatureDatabase,
) -> Result<Option<MalwareSignature>, String> {
    let hash = calculate_sha256(path)?;
    Ok(check_hash(&hash, signature_db))
}

fn build_new_bloom(hash_list: &[String]) -> Bloom<String> {
    println!("Construint un nou filtre Bloom...");
    let items_count = if hash_list.is_empty() { 1000 } else { hash_list.len() };
    
    let capacity = (items_count as f64 * 1.5) as usize; 
    let mut bloom = Bloom::new_for_fp_rate(capacity, 0.01);
    
    for hash in hash_list {
        bloom.set(hash);
    }
    bloom
}
