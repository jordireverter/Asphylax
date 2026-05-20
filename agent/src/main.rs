mod communication;
mod models;
mod scanner;
mod signatures;
mod updater;
mod yara_engine;
mod config;
mod decision_engine;
mod heuristics;
mod pe_analysis;
mod quarantine;
mod history;

fn main() {
    updater::start_update_loop();

    let signatures_map = match signatures::load_signatures() {
        Ok(map) => map,
        Err(error) => {
            eprintln!("Error carregant signatures: {}", error);
            return;
        }
    };

    let yara_engine = match yara_engine::YaraEngine::load() {
        Ok(engine) => engine,
        Err(error) => {
            eprintln!("Error carregant YARA: {}", error);
            return;
        }
    };

    let config = config::load_config()
    .expect("No s'ha pogut carregar config.json");

    if let Err(error) = communication::start_server(signatures_map, yara_engine, config) {
        eprintln!("Error iniciant l'agent: {}", error);
    }
}