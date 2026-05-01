use std::fs;
use std::path::{Path, PathBuf};

const YARA_RULES_DIR: &str = "../data/yara_rules";

pub struct YaraEngine {
    rules: yara_x::Rules,
}

impl YaraEngine {
    pub fn load() -> Result<Self, String> {
        println!("Carregant regles YARA...");

        let mut compiler = yara_x::Compiler::new();
        let rules_dir = Path::new(YARA_RULES_DIR);

        if !rules_dir.exists() {
            return Err(format!(
                "No existeix el directori de regles YARA: {}",
                YARA_RULES_DIR
            ));
        }

        let rule_files = collect_yara_files(rules_dir)?;

        if rule_files.is_empty() {
            return Err("No s'ha trobat cap fitxer .yar o .yara".to_string());
        }

        for path in &rule_files {
            let source = fs::read_to_string(path)
                .map_err(|e| format!("No es pot llegir {:?}: {}", path, e))?;

            compiler
                .add_source(source.as_str())
                .map_err(|e| format!("Error compilant {:?}: {}", path, e))?;
        }

        let rules = compiler.build();

        println!("Fitxers YARA carregats: {}", rule_files.len());

        Ok(Self { rules })
    }

    pub fn scan_file(&self, path: &str) -> Result<Vec<String>, String> {
    let bytes = fs::read(path)
        .map_err(|e| format!("Error llegint fitxer per YARA: {}", e))?;

    let mut scanner = yara_x::Scanner::new(&self.rules);

    let results = scanner
        .scan(&bytes)
        .map_err(|e| format!("Error escanejant amb YARA: {}", e))?;

    let mut detections = Vec::new();

    for matching_rule in results.matching_rules() {
        let rule_name = matching_rule.identifier().to_string();

        let mut severity = "unknown".to_string();
        let mut category = "unknown".to_string();
        let mut confidence = "unknown".to_string();

        for (key, value) in matching_rule.metadata() {
            let value_text = clean_metadata_value(&format!("{:?}", value));

            if key == "severity" {
                severity = value_text;
            } else if key == "category" {
                category = value_text;
            } else if key == "confidence" {
                confidence = value_text;
            }
        }

        detections.push(format!(
            "{} [severity={}, category={}, confidence={}]",
            rule_name, severity, category, confidence
        ));
    }

    Ok(detections)
    }
}

fn collect_yara_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();

    collect_yara_files_recursive(dir, &mut files)?;

    Ok(files)
}

fn collect_yara_files_recursive(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(dir)
        .map_err(|e| format!("No es pot llegir el directori {:?}: {}", dir, e))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("Error llegint entrada: {}", e))?;
        let path = entry.path();

        if path.is_dir() {
            collect_yara_files_recursive(&path, files)?;
        } else if is_yara_file(&path) {
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


fn clean_metadata_value(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .replace("String(", "")
        .replace("Integer(", "")
        .replace(")", "")
}