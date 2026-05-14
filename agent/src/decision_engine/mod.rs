use crate::models::Detection;

pub struct DecisionResult {
    pub score: i32,
    pub classification: String,
}

pub fn classify(detections: &[Detection]) -> DecisionResult {
    let mut score = 0;

    for detection in detections {
        match detection.engine.as_str() {
            "hash" => {
                // Malware segur
                return DecisionResult {
                    score: 100,
                    classification: "malware".to_string(),
                };
            }

            "yara" => {
                score += score_yara(detection);
            }

            "heuristic" => {
                score += detection.confidence;
            }

            _ => {}
        }
    }

    let classification = if score >= 80 {
        "malware"
    } else if score >= 50 {
        "suspicious"
    } else {
        "clean"
    };

    DecisionResult {
        score,
        classification: classification.to_string(),
    }
}

fn score_yara(detection: &Detection) -> i32 {
    match detection.severity.as_str() {
        "critical" => 80,
        "high" => 70,
        "medium" => 50,
        "low" => 30,
        _ => 40,
    }
}