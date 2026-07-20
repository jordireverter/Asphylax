use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::sync::mpsc::SyncSender;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use notify::{Watcher, RecursiveMode, Event, EventKind};
use serde::Serialize;

use crate::signatures::SignatureDatabase;
use crate::yara_engine::YaraEngine;
use crate::models::AppConfig;
use crate::scanner;
use crate::quarantine;
use crate::history;

const SCAN_COOLDOWN: Duration = Duration::from_secs(2);

// Anti-cooldown global compartit entre tots els events del watcher
static LAST_SCAN_TIMES: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();

fn get_scan_times() -> &'static Mutex<HashMap<String, Instant>> {
    LAST_SCAN_TIMES.get_or_init(|| Mutex::new(HashMap::new()))
}

// Estructura que representa un event de monitorització enviat al client via IPC
#[derive(Debug, Clone, Serialize)]
pub struct MonitorEvent {
    pub event_type: String,       // "threat_detected" | "file_scanned_clean" | "error"
    pub action: String,           // "create" | "modify" | "delete" | etc.
    pub path: String,
    pub score: i32,
    pub classification: String,
    pub detections: usize,
    pub message: String,
    pub auto_quarantined: bool,
}

pub struct AsphylaxFileMonitor {
    watcher: Option<notify::RecommendedWatcher>,
}

impl AsphylaxFileMonitor {
    pub fn new() -> Self {
        Self { watcher: None }
    }

    pub fn is_running(&self) -> bool {
        self.watcher.is_some()
    }

    /// Activa el monitor de disc en segon pla. Els events de detecció es propaguen
    /// cap al client Python a través del canal `event_sender`.
    pub fn start(
        &mut self,
        path_to_watch: &str,
        signature_db: Arc<SignatureDatabase>,
        yara_engine: Arc<YaraEngine>,
        config: Arc<AppConfig>,
        event_sender: SyncSender<MonitorEvent>,
    ) -> Result<(), String> {
        if self.watcher.is_some() {
            return Err("El monitor ja està actiu. Atura'l primer amb stop_monitoring.".to_string());
        }

        println!("[+] Monitor Asphylax activat al directori: {}", path_to_watch);

        // Clons que entren a la clausura del watcher (executa en un fil intern de notify)
        let sig_base = Arc::clone(&signature_db);
        let yara_base = Arc::clone(&yara_engine);
        let cfg_base = Arc::clone(&config);
        let sender = event_sender.clone();

        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                // Capturem el tipus d'acció (Create o Modify)
                let action_type = match event.kind {
                    EventKind::Create(_) => "create",
                    EventKind::Modify(_) => "modify",
                    _ => return,  // Ignorem altres tipus d'events
                };

                for path in event.paths {
                    let path_str = path.to_string_lossy().to_string();
                    let path_lower = path_str.replace('\\', "/").to_lowercase();

                    // ── Guardes de seguretat ──────────────────────────────────────────
                    // 1. Mai escanejar la quarantena per evitar bucles infinits
                    if path_lower.contains("/quarantine") {
                        continue;
                    }

                    // 2. Exclusions de ruta configurades per l'usuari
                    let mut is_excluded = false;
                    for excluded in &cfg_base.exclusions.paths {
                        if path_lower.starts_with(&excluded.replace('\\', "/").to_lowercase()) {
                            is_excluded = true;
                            break;
                        }
                    }
                    if is_excluded {
                        continue;
                    }

                    // 3. Exclusions d'extensió configurades per l'usuari
                    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                        let ext_fmt = format!(".{}", ext.to_lowercase());
                        if cfg_base.exclusions.extensions.iter().any(|e| e.to_lowercase() == ext_fmt) {
                            continue;
                        }
                    }

                    // 4. Anti-cooldown: evitem re-escanejar el mateix fitxer en < 2s
                    {
                        let mut scan_times = get_scan_times().lock().unwrap();
                        if let Some(last) = scan_times.get(&path_str) {
                            if last.elapsed() < SCAN_COOLDOWN {
                                continue;
                            }
                        }
                        scan_times.insert(path_str.clone(), Instant::now());
                        // Alliberem el mutex explícitament abans d'escanejar
                    }

                    // Només procesem fitxers regulars (no directoris ni symlinks)
                    if !path.is_file() {
                        continue;
                    }

                    println!("[Monitor] Interceptat: {}", path_str);

                    let sig_scan  = Arc::clone(&sig_base);
                    let yara_scan = Arc::clone(&yara_base);
                    let cfg_scan  = Arc::clone(&cfg_base);

                    match scanner::scan_path(&path_str, &sig_scan, &yara_scan, &cfg_scan) {
                        Ok(result) => {
                            // Únicament emetre events quan hi ha deteccions
                            if result.total_detections > 0 {
                                // ── Auto-quarantena ───────────────────────────────────
                                let mut auto_quarantined = false;

                                if cfg_scan.auto_quarantine.enabled {
                                    let should_quarantine = match cfg_scan
                                        .auto_quarantine
                                        .minimum_classification
                                        .as_str()
                                    {
                                        "suspicious" => matches!(
                                            result.classification.as_str(),
                                            "suspicious" | "malicious"
                                        ),
                                        "malicious" => result.classification == "malicious",
                                        _ => false,
                                    };

                                    if should_quarantine {
                                        if let Ok(entry) = quarantine::quarantine_file(&path_str) {
                                            let _ = history::add_history_entry(
                                                "auto_quarantine",
                                                Some(entry.original_path.clone()),
                                                &entry.status,
                                                None,
                                                &format!(
                                                    "Quarantena automàtica pel monitor: {}",
                                                    path_str
                                                ),
                                            );
                                            auto_quarantined = true;
                                            println!(
                                                "[MONITOR] Quarantena automàtica: {}",
                                                path_str
                                            );
                                        }
                                    }
                                }

                                // Registrem al historial
                                let _ = history::add_history_entry(
                                    "monitor_detection",
                                    Some(path_str.clone()),
                                    &result.classification,
                                    Some(result.final_score),
                                    &format!(
                                        "Detecció en temps real: {} detecció(ns)",
                                        result.total_detections
                                    ),
                                );

                                println!(
                                    "[ALERTA MONITOR] {} | Score: {} | Classificació: {} | AQ: {}",
                                    path_str,
                                    result.final_score,
                                    result.classification,
                                    auto_quarantined
                                );

                                // ── Enviem l'event al subscriptor IPC ────────────────
                                let event = MonitorEvent {
                                    event_type: "threat_detected".to_string(),
                                    action: action_type.to_string(),
                                    path: path_str.clone(),
                                    score: result.final_score,
                                    classification: result.classification.clone(),
                                    detections: result.total_detections,
                                    message: format!(
                                        "{} detecció(ns) trobada(es){}",
                                        result.total_detections,
                                        if auto_quarantined {
                                            " — fitxer en quarantena automàticament"
                                        } else {
                                            ""
                                        }
                                    ),
                                    auto_quarantined,
                                };

                                // try_send és no-bloquejant; si no hi ha subscriptor, descartem l'event
                                if let Err(e) = sender.try_send(event) {
                                    eprintln!(
                                        "[Monitor] No s'ha pogut enviar event al subscriptor: {}",
                                        e
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("[-] Error analitzant event de disc '{}': {}", path_str, e);
                        }
                    }
                }
            }
        })
        .map_err(|e| format!("Error creant watcher natiu: {}", e))?;

        watcher
            .watch(Path::new(path_to_watch), RecursiveMode::Recursive)
            .map_err(|e| format!("Error enllaçant ruta '{}' al watcher: {}", path_to_watch, e))?;

        self.watcher = Some(watcher);
        Ok(())
    }

    /// Atura el monitor de disc i tanca el canal d'events cap al client.
    pub fn stop(&mut self) {
        if let Some(watcher) = self.watcher.take() {
            drop(watcher); // Allibera el watcher i tots els seus fils interns
            println!("[*] Monitor aturat correctament.");
        }
    }
}
