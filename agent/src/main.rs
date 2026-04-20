mod communication;
mod models;
mod scanner;
mod signatures;

fn main() {
    if let Err(error) = communication::start_server() {
        eprintln!("Error iniciant l'agent: {}", error);
    }
}