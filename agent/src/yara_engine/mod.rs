use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration; 

use serde::Deserialize;

use crate::models::Detection;
use crate::paths;

#[derive(Debug, Deserialize)]
struct YaraBlacklist {
    disabled_rules: Vec<String>,
}

pub struct YaraEngine {
    rules: yara_x::Rules,
}

impl YaraEngine {
    pub fn load() -> Result<Self, String> {
        println!("Inicialitzant motor YARA...");

        let cache_file = paths::data_file("yara_rules.yarc");
        if let Ok(bytes) = fs::read(&cache_file) {
            println!("Carregant regles YARA precompilades des de la memòria cau (Instantani)...");
            if let Ok(rules) = yara_x::Rules::deserialize(&bytes) {
                return Ok(Self { rules });
            } else {
                eprintln!("La memòria cau YARA està corrupta. Es recompilarà de zero.");
            }
        }

        let rules_dir = paths::data_dir("yara_rules_validated");
        if !rules_dir.exists() {
            return Err(format!("No existeix el directori de regles YARA: {}", rules_dir.display()));
        }

        let blacklist = load_blacklist();
        let rule_files = collect_yara_files(&rules_dir, &blacklist)?;

        if rule_files.is_empty() {
            return Err("No s'ha trobat cap fitxer .yar o .yara".to_string());
        }

        println!("Compilant {} fitxers YARA de text pla en un sol bloc...", rule_files.len());
        
        let mut compiler = yara_x::Compiler::new();
        
        compiler.define_global("filepath", "").map_err(|e| e.to_string())?;
        compiler.define_global("filename", "").map_err(|e| e.to_string())?;
        compiler.define_global("extension", "").map_err(|e| e.to_string())?;

        let mut skipped = 0;

        for path in rule_files {
            match fs::read_to_string(&path) {
                Ok(source) => {
                    if let Err(error) = compiler.add_source(source.as_str()) {
                        skipped += 1;
                        eprintln!("Regla descartada {:?}: {}", path, error);
                    }
                }
                Err(e) => {
                    skipped += 1;
                    eprintln!("Error llegint {:?}: {}", path, e);
                }
            }
        }

        let rules = compiler.build();
        println!("Motor YARA llest. Fitxers YARA descartats: {}", skipped);

        if let Ok(serialized) = rules.serialize() {
            if let Err(e) = fs::write(&cache_file, serialized) {
                eprintln!("No s'ha pogut guardar la memòria cau YARA: {}", e);
            }
        }

        Ok(Self { rules })
    }

    pub fn scan_file(&self, path: &str, timeout_secs: u64) -> Result<Vec<Detection>, String> {
        let bytes = fs::read(path).map_err(|e| format!("Error llegint fitxer per YARA: {}", e))?;
        self.scan_bytes(path, &bytes, timeout_secs)
    }

    pub fn scan_bytes(&self, path: &str, bytes: &[u8], timeout_secs: u64) -> Result<Vec<Detection>, String> {
        let path_obj = Path::new(path);

        let filepath = path_obj.to_string_lossy().to_string();
        let filename = path_obj.file_name().and_then(|name| name.to_str()).unwrap_or("").to_string();
        let extension = path_obj.extension().and_then(|ext| ext.to_str()).unwrap_or("").to_string();

        let mut detections = Vec::new();

        let mut scanner = yara_x::Scanner::new(&self.rules);
        
        scanner.set_timeout(Duration::from_secs(timeout_secs));

        scanner.set_global("filepath", filepath.clone()).map_err(|e| format!("Error assignant global: {}", e))?;
        scanner.set_global("filename", filename.clone()).map_err(|e| format!("Error assignant global: {}", e))?;
        scanner.set_global("extension", extension.clone()).map_err(|e| format!("Error assignant global: {}", e))?;

        let results = scanner.scan(bytes).map_err(|e| format!("Error/Timeout escanejant amb YARA: {}", e))?;

        for matching_rule in results.matching_rules() {
            let rule_name = matching_rule.identifier().to_string();

            let mut severity = "medium".to_string();
            let mut category = "yara".to_string();
            let mut confidence = 70;
            let mut source = "yara".to_string();

            for (key, value) in matching_rule.metadata() {
                let value_text = clean_metadata_value(&format!("{:?}", value));

                if key == "severity" { severity = value_text; } 
                else if key == "category" { category = value_text; } 
                else if key == "confidence" { confidence = value_text.parse::<i32>().unwrap_or(70); } 
                else if key == "source" { source = value_text; }
            }

            detections.push(Detection {
                path: filepath.clone(),
                engine: "yara".to_string(),
                name: rule_name,
                category,
                severity,
                confidence,
                source,
            });
        }

        Ok(detections)
    }
}

fn load_blacklist() -> HashSet<String> {
    match fs::read_to_string(paths::data_file("yara_rule_blacklist.json")) {
        Ok(json) => {
            let parsed: Result<YaraBlacklist, _> = serde_json::from_str(&json);
            match parsed {
                Ok(blacklist) => blacklist.disabled_rules.into_iter().collect(),
                Err(error) => {
                    eprintln!("Error llegint blacklist YARA: {}", error);
                    HashSet::new()
                }
            }
        }
        Err(_) => HashSet::new(),
    }
}

fn collect_yara_files(dir: &Path, blacklist: &HashSet<String>) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    collect_yara_files_recursive(dir, &mut files, blacklist)?;
    Ok(files)
}

fn collect_yara_files_recursive(dir: &Path, files: &mut Vec<PathBuf>, blacklist: &HashSet<String>) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|e| format!("No es pot llegir el directori {:?}: {}", dir, e))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("Error llegint entrada: {}", e))?;
        let path = entry.path();

        if path.is_dir() {
            collect_yara_files_recursive(&path, files, blacklist)?;
        } else if is_yara_file(&path) && !is_blacklisted(&path, blacklist) {
            files.push(path);
        }
    }
    Ok(())
}

fn is_yara_file(path: &Path) -> bool {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("yar") | Some("yara") => true,
        _ => false,
    }
}

fn is_blacklisted(path: &Path, blacklist: &HashSet<String>) -> bool {
    let name = path.file_name().and_then(|file_name| file_name.to_str()).unwrap_or("");
    blacklist.contains(name)
}

fn clean_metadata_value(value: &str) -> String {
    value.trim().trim_matches('"').replace("String(", "").replace("Integer(", "").replace(")", "")
}
