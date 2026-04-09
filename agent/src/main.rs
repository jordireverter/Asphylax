mod communication;
mod models;

fn main() {
    if let Err(error) = communication::start_server() {
        eprintln!("Error iniciant l'agent: {}", error);
    }
}