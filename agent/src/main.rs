mod communication;
mod models;
mod scanner;

fn main() {
    if let Err(error) = communication::start_server() {
        eprintln!("Error iniciant l'agent: {}", error);
    }
}