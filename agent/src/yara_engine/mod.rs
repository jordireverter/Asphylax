use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::models::Detection;

const YARA_RULES_DIR: &str = "../data/yara_rules_validated";
const YARA_BLACKLIST_FILE: &str = "../data/yara_rule_blacklist.json";

pub struct YaraRuleSet {
    file_path: PathBuf,
    rules: yara_x::Rules,
}

pub struct YaraEngine {
    rule_sets: Vec<YaraRuleSet>,
}

#[derive(Debug, Deserialize)]
struct YaraBlacklist {
    disabled_rules: Vec<String>,
}

impl YaraEngine {
    pub fn load() -> Result<Self, String> {
        println!("Carregant regles YARA...");

        let rules_dir = Path::new(YARA_RULES_DIR);

        if !rules_dir.exists() {
            return Err(format!(
                "No existeix el directori de regles YARA: {}",
                YARA_RULES_DIR
            ));
        }

        let blacklist = load_blacklist();
        println!("Regles YARA a la blacklist: {}", blacklist.len());

        let rule_files = collect_yara_files(rules_dir, &blacklist)?;

        if rule_files.is_empty() {
            return Err("No s'ha trobat cap fitxer .yar o .yara".to_string());
        }

        let mut rule_sets = Vec::new();
        let mut skipped = 0;

        for path in rule_files {
            println!("Compilant regla YARA: {:?}", path);

            match compile_rule_file(&path) {
                Ok(rules) => {
                    rule_sets.push(YaraRuleSet {
                        file_path: path,
                        rules,
                    });
                }
                Err(error) => {
                    skipped += 1;
                    eprintln!("Regla descartada: {}", error);
                }
            }
        }

        println!("Paquets YARA carregats: {}", rule_sets.len());
        println!("Fitxers YARA descartats: {}", skipped);

        Ok(Self { rule_sets })
    }

    pub fn scan_file(&self, path: &str) -> Result<Vec<Detection>, String> {
        let bytes = fs::read(path)
            .map_err(|e| format!("Error llegint fitxer per YARA: {}", e))?;

        let path_obj = Path::new(path);

        let filepath = path_obj.to_string_lossy().to_string();

        let filename = path_obj
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("")
            .to_string();

        let extension = path_obj
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_string();

        let mut detections = Vec::new();

        for rule_set in &self.rule_sets {
            let mut scanner = yara_x::Scanner::new(&rule_set.rules);

            scanner
                .set_global("filepath", filepath.clone())
                .map_err(|e| format!("Error assignant global filepath: {}", e))?;

            scanner
                .set_global("filename", filename.clone())
                .map_err(|e| format!("Error assignant global filename: {}", e))?;

            scanner
                .set_global("extension", extension.clone())
                .map_err(|e| format!("Error assignant global extension: {}", e))?;

            let results = scanner.scan(&bytes).map_err(|e| {
                format!(
                    "Error escanejant amb YARA {:?}: {}",
                    rule_set.file_path, e
                )
            })?;

            for matching_rule in results.matching_rules() {
                let rule_name = matching_rule.identifier().to_string();

                let mut severity = "medium".to_string();
                let mut category = "yara".to_string();
                let mut confidence = 70;
                let mut source = "yara".to_string();

                for (key, value) in matching_rule.metadata() {
                    let value_text = clean_metadata_value(&format!("{:?}", value));

                    if key == "severity" {
                        severity = value_text;
                    } else if key == "category" {
                        category = value_text;
                    } else if key == "confidence" {
                        confidence = value_text.parse::<i32>().unwrap_or(70);
                    } else if key == "source" {
                        source = value_text;
                    }
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
        }

        Ok(detections)
    }
}

fn compile_rule_file(path: &Path) -> Result<yara_x::Rules, String> {
    let source = fs::read_to_string(path)
        .map_err(|e| format!("No es pot llegir {:?}: {}", path, e))?;

    let mut compiler = yara_x::Compiler::new();

    compiler
        .define_global("filepath", "")
        .map_err(|e| format!("Error definint global filepath: {}", e))?;

    compiler
        .define_global("filename", "")
        .map_err(|e| format!("Error definint global filename: {}", e))?;

    compiler
        .define_global("extension", "")
        .map_err(|e| format!("Error definint global extension: {}", e))?;

    compiler
        .add_source(source.as_str())
        .map_err(|e| format!("Error compilant {:?}: {}", path, e))?;

    Ok(compiler.build())
}

fn load_blacklist() -> HashSet<String> {
    match fs::read_to_string(YARA_BLACKLIST_FILE) {
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

fn collect_yara_files(
    dir: &Path,
    blacklist: &HashSet<String>,
) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();

    collect_yara_files_recursive(dir, &mut files, blacklist)?;

    Ok(files)
}

fn collect_yara_files_recursive(
    dir: &Path,
    files: &mut Vec<PathBuf>,
    blacklist: &HashSet<String>,
) -> Result<(), String> {
    let entries = fs::read_dir(dir)
        .map_err(|e| format!("No es pot llegir el directori {:?}: {}", dir, e))?;

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
        Some("yar") => true,
        Some("yara") => true,
        _ => false,
    }
}

fn is_blacklisted(path: &Path, blacklist: &HashSet<String>) -> bool {
    let name = path
        .file_name()
        .and_then(|file_name| file_name.to_str())
        .unwrap_or("");

    blacklist.contains(name)
}

fn clean_metadata_value(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .replace("String(", "")
        .replace("Integer(", "")
        .replace(")", "")
}