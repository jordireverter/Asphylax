use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use crate::models::{AppConfig, RequestMessage, ResponseMessage};
use crate::monitor::{AsphylaxFileMonitor, MonitorEvent};
use crate::scanner;
use crate::signatures::SignatureDatabase;
use crate::yara_engine::YaraEngine;
use crate::quarantine;
use crate::history;
use crate::config;
use crate::updater;

const ADDRESS: &str = "127.0.0.1:7878";

// Estat global compartit entre totes les connexions del servidor
struct ServerState {
    signature_db: Arc<SignatureDatabase>,
    yara_engine:  Arc<YaraEngine>,
    config:       Arc<AppConfig>,
    monitor:      Arc<Mutex<AsphylaxFileMonitor>>,
    // Canal de sortida dels events del monitor cap al subscriptor actiu.
    // Creem un canal nou a cada `start_monitoring` i desem el Receiver aquí fins que
    // un client es connecti amb `subscribe_monitor_events`.
    event_rx:     Arc<Mutex<Option<Receiver<MonitorEvent>>>>,
}

pub fn start_server(
    signature_db: SignatureDatabase,
    yara_engine: YaraEngine,
    config: AppConfig,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(ADDRESS)?;
    println!("[+] Agent Asphylax escoltant via IPC local a {}", ADDRESS);
    updater::start_update_loop();

    // Encapsulem tots els recursos compartits en un únic Arc per facilitar els clons per fil
    let state = Arc::new(ServerState {
        signature_db: Arc::new(signature_db),
        yara_engine:  Arc::new(yara_engine),
        config:       Arc::new(config),
        monitor:      Arc::new(Mutex::new(AsphylaxFileMonitor::new())),
        event_rx:     Arc::new(Mutex::new(None)),
    });

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                // Cada connexió s'atén en un fil dedicat per evitar bloquejos
                // (especialment crític per a scan_progress i subscribe_monitor_events)
                let state_clone = Arc::clone(&state);
                std::thread::spawn(move || {
                    if let Err(e) = handle_client(stream, state_clone) {
                        eprintln!("[-] Error gestionant client IPC: {}", e);
                    }
                });
            }
            Err(e) => {
                eprintln!("[-] Error acceptant connexió IPC: {}", e);
            }
        }
    }

    Ok(())
}

fn handle_client(
    mut stream: TcpStream,
    state: Arc<ServerState>,
) -> std::io::Result<()> {
    // Llegim la comanda JSON d'una sola línia
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut input  = String::new();
    reader.read_line(&mut input)?;

    let request: Result<RequestMessage, _> = serde_json::from_str(&input);

    let response = match request {
        Err(_) => ResponseMessage {
            status:  "error".to_string(),
            message: "JSON invàlid a la trama rebuda".to_string(),
            data:    None,
        },

        Ok(req) => match req.action.as_str() {

            // ── Ping ─────────────────────────────────────────────────────────────
            "ping" => ResponseMessage {
                status:  "ok".to_string(),
                message: "Agent actiu".to_string(),
                data:    None,
            },

            // ── Scan normal (fitxer o directori) ─────────────────────────────────
            "scan" => match req.path {
                None => missing_path_error(),
                Some(path) => {
                    let active_config = match config::load_config() {
                        Ok(c)  => c,
                        Err(e) => return send_and_return(&mut stream, error_response(e)),
                    };

                    match scanner::scan_path(
                        &path,
                        &state.signature_db,
                        &state.yara_engine,
                        &active_config,
                    ) {
                        Ok(result) => {
                            let _ = history::add_history_entry(
                                "scan",
                                Some(path.clone()),
                                &result.classification,
                                Some(result.final_score),
                                &format!(
                                    "Fitxers escanejats: {}, deteccions: {}",
                                    result.scanned_files, result.total_detections
                                ),
                            );
                            ResponseMessage {
                                status:  "ok".to_string(),
                                message: "Scan completat".to_string(),
                                data:    Some(serde_json::to_value(result).unwrap()),
                            }
                        }
                        Err(e) => error_response(e),
                    }
                }
            },

            // ── Scan massiu amb progrés en temps real ─────────────────────────────
            "scan_progress" => match req.path {
                None => missing_path_error(),
                Some(path) => {
                    let active_config = match config::load_config() {
                        Ok(c)  => c,
                        Err(e) => {
                            write_json_line(&mut stream, &serde_json::json!({
                                "type": "done", "status": "error", "message": e, "data": null
                            }))?;
                            return Ok(());
                        }
                    };

                    // Arc compartit entre el fil principal i el callback de progrés
                    let progress_stream = Arc::new(Mutex::new(stream.try_clone()?));
                    let progress_clone  = Arc::clone(&progress_stream);

                    let result = scanner::scan_path_with_progress(
                        &path,
                        &state.signature_db,
                        &state.yara_engine,
                        &active_config,
                        move |scanned, total| {
                            let percent = if total == 0 { 100 } else { (scanned * 100) / total };
                            let mut s = progress_clone
                                .lock()
                                .map_err(|_| "No s'ha pogut bloquejar el socket de progrés".to_string())?;
                            write_json_line(&mut *s, &serde_json::json!({
                                "type":          "progress",
                                "percent":        percent,
                                "scanned_files":  scanned,
                                "total_files":    total,
                            }))
                            .map_err(|e| format!("Error enviant progrés: {}", e))
                        },
                    );

                    match result {
                        Ok(r) => {
                            let _ = history::add_history_entry(
                                "scan_progress",
                                Some(path.clone()),
                                &r.classification,
                                Some(r.final_score),
                                &format!(
                                    "Fitxers escanejats: {}, deteccions: {}",
                                    r.scanned_files, r.total_detections
                                ),
                            );
                            write_json_line(&mut stream, &serde_json::json!({
                                "type":    "done",
                                "status":  "ok",
                                "message": "Scan completat",
                                "data":    r,
                            }))?;
                        }
                        Err(e) => {
                            write_json_line(&mut stream, &serde_json::json!({
                                "type":    "done",
                                "status":  "error",
                                "message": e,
                                "data":    null,
                            }))?;
                        }
                    }
                    return Ok(());
                }
            },

            // ── Quick scan ────────────────────────────────────────────────────────
            "quick_scan" => {
                let active_config = match config::load_config() {
                    Ok(c)  => c,
                    Err(e) => return send_and_return(&mut stream, error_response(e)),
                };

                match scanner::quick_scan(&state.signature_db, &state.yara_engine, &active_config) {
                    Ok(result) => {
                        let _ = history::add_history_entry(
                            "quick_scan",
                            Some("Quick scan".to_string()),
                            &result.classification,
                            Some(result.final_score),
                            &format!(
                                "Fitxers escanejats: {}, deteccions: {}",
                                result.scanned_files, result.total_detections
                            ),
                        );
                        ResponseMessage {
                            status:  "ok".to_string(),
                            message: "Quick scan completat".to_string(),
                            data:    Some(serde_json::to_value(result).unwrap()),
                        }
                    }
                    Err(e) => error_response(e),
                }
            },

            // ── Inicia la monitorització en temps real ────────────────────────────
            "start_monitoring" => match req.path {
                None => missing_path_error(),
                Some(path) => {
                    // Creem un canal nou bounded (capacitat 256 events) per cada sessió de monitoratge.
                    // El Sender entra al monitor; el Receiver queda en espera fins que el client
                    // es connecti amb `subscribe_monitor_events`.
                    let (tx, rx) = mpsc::sync_channel::<MonitorEvent>(256);

                    // Emmagatzemem el Receiver per al subscriptor
                    {
                        let mut rx_guard = state.event_rx.lock().unwrap();
                        *rx_guard = Some(rx);
                    }

                    // Carreguem la configuració fresca per al monitor
                    let active_config = match config::load_config() {
                        Ok(c)  => c,
                        Err(e) => return send_and_return(&mut stream, error_response(e)),
                    };

                    let mut mon = state.monitor.lock().unwrap();
                    match mon.start(
                        &path,
                        Arc::clone(&state.signature_db),
                        Arc::clone(&state.yara_engine),
                        Arc::new(active_config),
                        tx,
                    ) {
                        Ok(()) => {
                            let _ = history::add_history_entry(
                                "monitor_start",
                                Some(path.clone()),
                                "ok",
                                None,
                                &format!("Monitor iniciat a: {}", path),
                            );
                            ResponseMessage {
                                status:  "ok".to_string(),
                                message: format!("Monitor actiu a: {}", path),
                                data:    Some(serde_json::json!({ "path": path })),
                            }
                        }
                        Err(e) => error_response(e),
                    }
                }
            },

            // ── Atura la monitorització ───────────────────────────────────────────
            "stop_monitoring" => {
                {
                    let mut mon = state.monitor.lock().unwrap();
                    mon.stop(); // Destrueix el watcher → tanca el canal (Sender es destrueix)
                }
                // Buidem el receiver pendent (si el client mai es va subscriure)
                {
                    let mut rx_guard = state.event_rx.lock().unwrap();
                    *rx_guard = None;
                }
                let _ = history::add_history_entry(
                    "monitor_stop", None, "ok", None, "Monitor aturat"
                );
                ResponseMessage {
                    status:  "ok".to_string(),
                    message: "Monitor aturat correctament".to_string(),
                    data:    None,
                }
            },

            // ── Estat del monitor ─────────────────────────────────────────────────
            "get_monitor_status" => {
                let running = state.monitor.lock().unwrap().is_running();
                ResponseMessage {
                    status:  "ok".to_string(),
                    message: if running { "running" } else { "stopped" }.to_string(),
                    data:    Some(serde_json::json!({ "running": running })),
                }
            },

            // ── Streaming d'events del monitor cap al client Python ────────────────
            //
            // Aquesta acció és persistent: manté la connexió TCP oberta i envia
            // una línia JSON per cada event de detecció que el monitor produeixi.
            // El canal es tanca automàticament quan `stop_monitoring` destrueix el Sender.
            "subscribe_monitor_events" => {
                // Movem el Receiver fora del Mutex (només un subscriptor alhora)
                let rx = {
                    let mut guard = state.event_rx.lock().unwrap();
                    guard.take()
                };

                match rx {
                    None => {
                        // Cap monitor actiu o ja hi ha un subscriptor connectat
                        return send_and_return(&mut stream, ResponseMessage {
                            status:  "error".to_string(),
                            message: "Cap monitor actiu. Inicia'l primer amb start_monitoring.".to_string(),
                            data:    None,
                        });
                    }
                    Some(rx) => {
                        // Confirmem la connexió al client
                        write_json_line(&mut stream, &serde_json::json!({
                            "type":    "subscribed",
                            "status":  "ok",
                            "message": "Subscripció activa. Rebent events en temps real.",
                        }))?;

                        // Bucle de streaming: bloqueig amb timeout per poder detectar
                        // si el client ha desconnectat (error d'escriptura)
                        loop {
                            match rx.recv_timeout(Duration::from_secs(5)) {
                                Ok(event) => {
                                    // Enviem l'event de detecció al client
                                    let payload = serde_json::json!({
                                        "type":  "monitor_event",
                                        "event": event,
                                    });
                                    if write_json_line(&mut stream, &payload).is_err() {
                                        // El client ha desconnectat
                                        break;
                                    }
                                }
                                Err(mpsc::RecvTimeoutError::Timeout) => {
                                    // Enviem un heartbeat per detectar desconnexions del client
                                    if write_json_line(&mut stream, &serde_json::json!({
                                        "type": "heartbeat"
                                    })).is_err() {
                                        break;
                                    }
                                }
                                Err(mpsc::RecvTimeoutError::Disconnected) => {
                                    // El monitor ha estat aturat (Sender destruït)
                                    let _ = write_json_line(&mut stream, &serde_json::json!({
                                        "type":    "monitor_stopped",
                                        "message": "El monitor ha estat aturat des de l'agent.",
                                    }));
                                    break;
                                }
                            }
                        }

                        // No restaurem el receiver (el canal ja pot estar tancat)
                        return Ok(());
                    }
                }
            },

            // ── Quarantena ───────────────────────────────────────────────────────
            "quarantine" => match req.path {
                None => missing_path_error(),
                Some(path) => match quarantine::quarantine_file(&path) {
                    Ok(entry) => {
                        let _ = history::add_history_entry(
                            "quarantine",
                            Some(entry.original_path.clone()),
                            &entry.status,
                            None,
                            &format!("Fitxer mogut a: {}", entry.quarantine_path),
                        );
                        ResponseMessage {
                            status:  "ok".to_string(),
                            message: "Fitxer enviat a quarantena".to_string(),
                            data:    Some(serde_json::to_value(entry).unwrap()),
                        }
                    }
                    Err(e) => error_response(e),
                },
            },

            "list_quarantine" => match quarantine::list_quarantine() {
                Ok(entries) => ResponseMessage {
                    status:  "ok".to_string(),
                    message: "Llista de quarantena carregada".to_string(),
                    data:    Some(serde_json::to_value(entries).unwrap()),
                },
                Err(e) => error_response(e),
            },

            "restore_quarantine" => match req.path {
                None => ResponseMessage {
                    status:  "error".to_string(),
                    message: "Falta l'ID de quarantena".to_string(),
                    data:    None,
                },
                Some(id) => match quarantine::restore_quarantine(&id) {
                    Ok(entry) => {
                        let _ = history::add_history_entry(
                            "restore_quarantine",
                            Some(entry.original_path.clone()),
                            &entry.status,
                            None,
                            "Fitxer restaurat des de quarantena",
                        );
                        ResponseMessage {
                            status:  "ok".to_string(),
                            message: "Fitxer restaurat correctament".to_string(),
                            data:    Some(serde_json::to_value(entry).unwrap()),
                        }
                    }
                    Err(e) => error_response(e),
                },
            },

            "delete_quarantine" => match req.path {
                None => ResponseMessage {
                    status:  "error".to_string(),
                    message: "Falta l'ID de quarantena".to_string(),
                    data:    None,
                },
                Some(id) => match quarantine::delete_quarantine(&id) {
                    Ok(entry) => {
                        let _ = history::add_history_entry(
                            "delete_quarantine",
                            Some(entry.original_path.clone()),
                            &entry.status,
                            None,
                            "Fitxer eliminat definitivament de quarantena",
                        );
                        ResponseMessage {
                            status:  "ok".to_string(),
                            message: "Fitxer eliminat definitivament".to_string(),
                            data:    Some(serde_json::to_value(entry).unwrap()),
                        }
                    }
                    Err(e) => error_response(e),
                },
            },

            // ── Historial ────────────────────────────────────────────────────────
            "list_history" => match history::list_history() {
                Ok(entries) => ResponseMessage {
                    status:  "ok".to_string(),
                    message: "Historial carregat".to_string(),
                    data:    Some(serde_json::to_value(entries).unwrap()),
                },
                Err(e) => error_response(e),
            },

            // ── Configuració ─────────────────────────────────────────────────────
            "get_config" => match config::load_config() {
                Ok(cfg) => ResponseMessage {
                    status:  "ok".to_string(),
                    message: "Configuració carregada".to_string(),
                    data:    Some(serde_json::to_value(cfg).unwrap()),
                },
                Err(e) => error_response(e),
            },

            "save_config" => match req.data {
                None => ResponseMessage {
                    status:  "error".to_string(),
                    message: "Falta el camp 'data' amb la configuració".to_string(),
                    data:    None,
                },
                Some(val) => match serde_json::from_value::<AppConfig>(val) {
                    Err(e) => error_response(format!("Config invàlida: {}", e)),
                    Ok(cfg) => match config::save_config(&cfg) {
                        Ok(_)  => ResponseMessage {
                            status:  "ok".to_string(),
                            message: "Configuració guardada".to_string(),
                            data:    None,
                        },
                        Err(e) => error_response(e),
                    },
                },
            },

            // ── Acció desconeguda ─────────────────────────────────────────────────
            unknown => ResponseMessage {
                status:  "error".to_string(),
                message: format!("Acció desconeguda: '{}'", unknown),
                data:    None,
            },
        },
    };

    // Resposta JSON estàndard (una sola línia)
    write_json_line(&mut stream, &serde_json::to_value(&response).unwrap())?;
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Escriu un valor JSON serialitzat seguit d'un salt de línia i fa flush.
fn write_json_line(stream: &mut TcpStream, value: &serde_json::Value) -> std::io::Result<()> {
    let line = serde_json::to_string(value)? + "\n";
    stream.write_all(line.as_bytes())?;
    stream.flush()
}

/// Envia una resposta estàndard i retorna Ok(()) per al patró `return`.
fn send_and_return(stream: &mut TcpStream, response: ResponseMessage) -> std::io::Result<()> {
    write_json_line(stream, &serde_json::to_value(&response).unwrap())
}

fn error_response(message: impl Into<String>) -> ResponseMessage {
    ResponseMessage {
        status:  "error".to_string(),
        message: message.into(),
        data:    None,
    }
}

fn missing_path_error() -> ResponseMessage {
    ResponseMessage {
        status:  "error".to_string(),
        message: "Falta el camp 'path' a la petició".to_string(),
        data:    None,
    }
}
