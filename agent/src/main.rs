mod communication;
mod models;
mod scanner;
mod signatures;
mod updater;

fn main() {
    updater::start_update_loop();

    if let Err(error) = communication::start_server() {
        eprintln!("Error iniciant l'agent: {}", error);
    }
}

