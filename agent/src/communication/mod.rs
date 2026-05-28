use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use crate::models::{AppConfig, RequestMessage, ResponseMessage};
use crate::scanner;
use crate::signatures::SignaturesMap;
use crate::yara_engine::YaraEngine;
use crate::quarantine;
use crate::history;
use crate::config;

const ADDRESS: &str = "127.0.0.1:7878";

pub fn start_server(
    signatures_map: SignaturesMap,
    yara_engine: YaraEngine,
    config: AppConfig
) -> std::io::Result<()> {
    let listener = TcpListener::bind(ADDRESS)?;
    println!("Agent escoltant a {}", ADDRESS);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = handle_client(stream, &signatures_map, &yara_engine, &config) {
                    eprintln!("Error gestionant client: {}", error);
                }
            }
            Err(error) => {
                eprintln!("Error acceptant connexió: {}", error);
            }
        }
    }

    Ok(())
}

fn handle_client(
    mut stream: TcpStream,
    signatures_map: &SignaturesMap,
    yara_engine: &YaraEngine,
    config: &AppConfig,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut input = String::new();

    reader.read_line(&mut input)?;

    let request: Result<RequestMessage, _> = serde_json::from_str(&input);

    let response = match request {
        Ok(req) => match req.action.as_str() {
            "ping" => ResponseMessage {
                status: "ok".to_string(),
                message: "Agent actiu".to_string(),
                data: None,
            },
            "scan_progress" => match req.path {
                Some(path) => {
                    let progress_stream = Arc::new(Mutex::new(stream.try_clone()?));
                    let progress_stream_clone = Arc::clone(&progress_stream);
                    let active_config = match config::load_config() {
                        Ok(cfg) => cfg,
                        Err(error) => {
                            let error_json = serde_json::json!({
                                "type": "done",
                                "status": "error",
                                "message": error,
                                "data": null
                            }).to_string() + "\n";

                            stream.write_all(error_json.as_bytes())?;
                            stream.flush()?;
                            return Ok(());
                        }
                    };
                    let scan_result = scanner::scan_path_with_progress(
                        &path,
                        signatures_map,
                        yara_engine,
                        &active_config,
                        move |scanned, total| {
                            let percent = if total == 0 {
                                100
                            } else {
                                (scanned * 100) / total
                            };

                            let progress_json = serde_json::json!({
                                "type": "progress",
                                "percent": percent,
                                "scanned_files": scanned,
                                "total_files": total
                            })
                            .to_string()
                                + "\n";

                            let mut locked_stream = progress_stream_clone
                                .lock()
                                .map_err(|_| "No s'ha pogut bloquejar el socket de progrés".to_string())?;

                            locked_stream
                                .write_all(progress_json.as_bytes())
                                .map_err(|e| format!("Error enviant progrés: {}", e))?;

                            locked_stream
                                .flush()
                                .map_err(|e| format!("Error fent flush: {}", e))?;

                            Ok(())
                        },
                    );

                    match scan_result {
                        Ok(result) => {
                            let _ = history::add_history_entry(
                                "scan_progress",
                                Some(path.clone()),
                                &result.classification,
                                Some(result.final_score),
                                &format!(
                                    "Fitxers escanejats: {}, deteccions totals: {}",
                                    result.scanned_files,
                                    result.total_detections
                                ),
                            );
                            println!("================ RESULTAT SCAN ================");
                            println!("Fitxers escanejats: {}", result.scanned_files);
                            println!("Deteccions totals: {}", result.total_detections);
                            println!("Fitxers amb deteccions: {}", result.files.len());
                            println!("Score global: {}", result.final_score);
                            println!("Classificació global: {}", result.classification);
                            println!("===============================================");
                            let final_json = serde_json::json!({
                                "type": "done",
                                "status": "ok",
                                "message": "Scan completat",
                                "data": result
                            })
                            .to_string()
                                + "\n";

                            stream.write_all(final_json.as_bytes())?;
                            stream.flush()?;
                            return Ok(());
                        }
                        Err(error) => {
                            let error_json = serde_json::json!({
                                "type": "done",
                                "status": "error",
                                "message": error,
                                "data": null
                            })
                            .to_string()
                                + "\n";

                            stream.write_all(error_json.as_bytes())?;
                            stream.flush()?;
                            return Ok(());
                        }
                    }
                }
                None => ResponseMessage {
                    status: "error".to_string(),
                    message: "Falta el camp 'path'".to_string(),
                    data: None,
                },
            },
            "scan" => match req.path {
                Some(path) => {
                    let active_config = match config::load_config() {
                        Ok(cfg) => cfg,
                        Err(error) => {
                            return Ok(send_plain_response(
                                &mut stream,
                                ResponseMessage {
                                    status: "error".to_string(),
                                    message: error,
                                    data: None,
                                },
                            )?);
                        }
                    };

                    match scanner::scan_path(&path, signatures_map, yara_engine, &active_config) {
                        Ok(result) => {
                            let _ = history::add_history_entry(
                                "scan",
                                Some(path.clone()),
                                &result.classification,
                                Some(result.final_score),
                                &format!(
                                    "Fitxers escanejats: {}, deteccions totals: {}",
                                    result.scanned_files,
                                    result.total_detections
                                ),
                            );

                            ResponseMessage {
                                status: "ok".to_string(),
                                message: "Scan completat".to_string(),
                                data: Some(serde_json::to_value(result).unwrap()),
                            }
                        }
                        Err(error) => ResponseMessage {
                            status: "error".to_string(),
                            message: error,
                            data: None,
                        },
                    }
                }
                None => ResponseMessage {
                    status: "error".to_string(),
                    message: "Falta el camp 'path'".to_string(),
                    data: None,
                },
            },

            "quarantine" => {
                match req.path {
                    Some(path) => {
                        match quarantine::quarantine_file(&path) {
                            Ok(entry) => {
                                let _ = history::add_history_entry(
                                    "quarantine",
                                    Some(entry.original_path.clone()),
                                    &entry.status,
                                    None,
                                    &format!("Fitxer mogut a: {}", entry.quarantine_path),
                                );

                                ResponseMessage {
                                    status: "ok".to_string(),
                                    message: "Fitxer enviat a quarantena".to_string(),
                                    data: Some(serde_json::to_value(entry).unwrap()),
                                }
                            },
                            Err(error) => ResponseMessage {
                                status: "error".to_string(),
                                message: error,
                                data: None,
                            },
                        }
                    }
                    None => ResponseMessage {
                        status: "error".to_string(),
                        message: "Falta el camp 'path'".to_string(),
                        data: None,
                    },
                }
            },

            "list_quarantine" => match quarantine::list_quarantine() {
                Ok(entries) => ResponseMessage {
                    status: "ok".to_string(),
                    message: "Llista de quarantena carregada".to_string(),
                    data: Some(serde_json::to_value(entries).unwrap()),
                },
                Err(error) => ResponseMessage {
                    status: "error".to_string(),
                    message: error,
                    data: None,
                },
            },


            "restore_quarantine" => {
                match req.path {
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
                                status: "ok".to_string(),
                                message: "Fitxer restaurat correctament".to_string(),
                                data: Some(serde_json::to_value(entry).unwrap()),
                            }
                        },
                        Err(error) => ResponseMessage {
                            status: "error".to_string(),
                            message: error,
                            data: None,
                        },
                    },
                    None => ResponseMessage {
                        status: "error".to_string(),
                        message: "Falta l'ID de quarantena".to_string(),
                        data: None,
                    },
                }
            },


            "delete_quarantine" => {
                match req.path {
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
                                status: "ok".to_string(),
                                message: "Fitxer eliminat definitivament".to_string(),
                                data: Some(serde_json::to_value(entry).unwrap()),
                            }
                        },
                        Err(error) => ResponseMessage {
                            status: "error".to_string(),
                            message: error,
                            data: None,
                        },
                    },
                    None => ResponseMessage {
                        status: "error".to_string(),
                        message: "Falta l'ID de quarantena".to_string(),
                        data: None,
                    },
                }
            },


            "list_history" => match history::list_history() {
                Ok(entries) => ResponseMessage {
                    status: "ok".to_string(),
                    message: "Historial carregat".to_string(),
                    data: Some(serde_json::to_value(entries).unwrap()),
                },
                Err(error) => ResponseMessage {
                    status: "error".to_string(),
                    message: error,
                    data: None,
                },
            },


            "get_config" => match config::load_config() {
                Ok(cfg) => ResponseMessage {
                    status: "ok".to_string(),
                    message: "Configuració carregada".to_string(),
                    data: Some(serde_json::to_value(cfg).unwrap()),
                },

                Err(error) => ResponseMessage {
                    status: "error".to_string(),
                    message: error,
                    data: None,
                },
            },

            "save_config" => match req.data {
                Some(config_value) => {
                    let config_data: Result<AppConfig, _> = serde_json::from_value(config_value);

                    match config_data {
                        Ok(cfg) => match config::save_config(&cfg) {
                            Ok(_) => ResponseMessage {
                                status: "ok".to_string(),
                                message: "Configuració guardada".to_string(),
                                data: None,
                            },
                            Err(error) => ResponseMessage {
                                status: "error".to_string(),
                                message: error,
                                data: None,
                            },
                        },
                        Err(error) => ResponseMessage {
                            status: "error".to_string(),
                            message: format!("Config invàlida: {}", error),
                            data: None,
                        },
                    }
                }
                None => ResponseMessage {
                    status: "error".to_string(),
                    message: "Falta config".to_string(),
                    data: None,
                },
            },


            "quick_scan" => {
                let active_config = match config::load_config() {
                    Ok(cfg) => cfg,
                    Err(error) => {
                        return Ok(send_plain_response(
                            &mut stream,
                            ResponseMessage {
                                status: "error".to_string(),
                                message: error,
                                data: None,
                            },
                        )?);
                    }
                };

                match scanner::quick_scan(signatures_map, yara_engine, &active_config) {
                    Ok(result) => {
                        let _ = history::add_history_entry(
                            "quick_scan",
                            Some("Quick scan".to_string()),
                            &result.classification,
                            Some(result.final_score),
                            &format!(
                                "Fitxers escanejats: {}, deteccions totals: {}",
                                result.scanned_files,
                                result.total_detections
                            ),
                        );

                        ResponseMessage {
                            status: "ok".to_string(),
                            message: "Quick scan completat".to_string(),
                            data: Some(serde_json::to_value(result).unwrap()),
                        }
                    }
                    Err(error) => ResponseMessage {
                        status: "error".to_string(),
                        message: error,
                        data: None,
                    },
                }
            },

            _ => ResponseMessage {
                status: "error".to_string(),
                message: format!("Acció desconeguda: {}", req.action),
                data: None,
            },
        },

        Err(_) => ResponseMessage {
            status: "error".to_string(),
            message: "JSON invàlid".to_string(),
            data: None,
        },
    };

    let response_json = serde_json::to_string(&response)? + "\n";
    stream.write_all(response_json.as_bytes())?;
    stream.flush()?;

    Ok(())
}


fn send_plain_response(
    stream: &mut TcpStream,
    response: ResponseMessage,
) -> std::io::Result<()> {
    let response_json = serde_json::to_string(&response)? + "\n";
    stream.write_all(response_json.as_bytes())?;
    stream.flush()?;
    Ok(())
}