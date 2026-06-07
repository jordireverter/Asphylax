use std::fs;

use regex::{Regex, RegexBuilder};

use crate::models::{PartialSignature, PartialSignaturesDatabase};
use crate::paths;

pub enum PartialMatcher {
    Literal {
        value: String,
        case_sensitive: bool,
    },
    Regex {
        regex: Regex,
    },
}

pub struct LoadedPartialSignature {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub confidence: i32,
    pub matcher: PartialMatcher,
}

pub fn load_partial_signatures() -> Result<Vec<LoadedPartialSignature>, String> {
    println!("Carregant signatures parcials...");

    let content = fs::read_to_string(paths::data_file("patterns.json"))
        .map_err(|e| format!("Error llegint patrons: {}", e))?;

    let db: PartialSignaturesDatabase = serde_json::from_str(&content)
        .map_err(|e| format!("Error parsejant patrons JSON: {}", e))?;

    let mut loaded_patterns = Vec::new();

    for pattern in db.entries {
        if !pattern.enabled {
            continue;
        }

        let loaded = compile_partial_signature(pattern)?;
        loaded_patterns.push(loaded);
    }

    println!(
        "Signatures parcials carregades: {}",
        loaded_patterns.len()
    );

    Ok(loaded_patterns)
}

fn compile_partial_signature(
    pattern: PartialSignature,
) -> Result<LoadedPartialSignature, String> {
    let case_sensitive = pattern.case_sensitive.unwrap_or(false);

    let matcher = match pattern.pattern_type.as_str() {
        "literal" => {
            let value = if case_sensitive {
                pattern.pattern.clone()
            } else {
                pattern.pattern.to_lowercase()
            };

            PartialMatcher::Literal {
                value,
                case_sensitive,
            }
        }

        "regex" => {
            let regex = RegexBuilder::new(&pattern.pattern)
                .case_insensitive(!case_sensitive)
                .build()
                .map_err(|e| {
                    format!(
                        "Regex invàlid a la signatura parcial '{}': {}",
                        pattern.name, e
                    )
                })?;

            PartialMatcher::Regex { regex }
        }

        other => {
            return Err(format!(
                "Tipus de patró desconegut '{}'. Usa 'literal' o 'regex'.",
                other
            ));
        }
    };

    Ok(LoadedPartialSignature {
        id: pattern.id,
        name: pattern.name,
        severity: pattern.severity,
        confidence: pattern.confidence,
        matcher,
    })
}

pub fn check_partial_signatures(
    path: &str,
    patterns: &[LoadedPartialSignature],
) -> Result<Vec<String>, String> {
    let content = fs::read(path)
        .map_err(|e| format!("Error llegint fitxer per patrons: {}", e))?;

    let content_text = String::from_utf8_lossy(&content);
    let content_lower = content_text.to_lowercase();

    let mut detections = Vec::new();

    for pattern in patterns {
        let matched = match &pattern.matcher {
            PartialMatcher::Literal {
                value,
                case_sensitive,
            } => {
                if *case_sensitive {
                    content_text.contains(value)
                } else {
                    content_lower.contains(value)
                }
            }

            PartialMatcher::Regex { regex } => regex.is_match(&content_text),
        };

        if matched {
            detections.push(format!(
                "{} [severity={}, confidence={}]",
                pattern.name, pattern.severity, pattern.confidence
            ));
        }
    }

    Ok(detections)
}
