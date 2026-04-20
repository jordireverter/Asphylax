use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};

use crate::models::{RequestMessage, ResponseMessage};
use crate::scanner;

const ADDRESS: &str = "127.0.0.1:7878";

pub fn start_server() -> std::io::Result<()> {
    let listener = TcpListener::bind(ADDRESS)?;
    println!("Agent escoltant a {}", ADDRESS);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = handle_client(stream) {
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

fn handle_client(mut stream: TcpStream) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut input = String::new();

    reader.read_line(&mut input)?;

    let request: Result<RequestMessage, _> = serde_json::from_str(&input);

    let response = match request {
    Ok(req) => {
        match req.action.as_str() {

            "ping" => ResponseMessage {
                status: "ok".to_string(),
                message: "Agent actiu".to_string(),
                data: None,
            },

            "scan" => {
                match req.path {
                    Some(path) => {
                        match scanner::scan_path(&path) {
                            Ok(result) => ResponseMessage {
                                status: "ok".to_string(),
                                message: "Scan completat".to_string(),
                                data: Some(result),
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
            }
            
            _ => ResponseMessage {
                status: "error".to_string(),
                message: format!("Acció desconeguda: {}", req.action),
                data: None,
            },
        }
    }

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