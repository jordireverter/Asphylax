mod communication;
mod config;
mod decision_engine;
mod heuristics;
mod history;
mod logger;
mod models;
mod monitor;         // ← Mòdul de monitorització en temps real
mod paths;
mod partial_signatures;
mod pe_analysis;
mod quarantine;
mod scanner;
mod signatures;
mod updater;
mod yara_engine;

fn main() {
    let handle = std::thread::Builder::new()
        .name("asphylax-agent-main".to_string())
        .stack_size(64 * 1024 * 1024)
        .spawn(run_agent);

    match handle {
        Ok(thread) => {
            if thread.join().is_err() {
                eprintln!("[-] L'agent s'ha aturat per un error intern.");
            }
        }
        Err(e) => eprintln!("[-] No s'ha pogut arrencar el fil principal de l'agent: {}", e),
    }
}

fn run_agent() {
    // Inicialització de l'actualitzador automàtic de signatures en segon pla
    // Carreguem la base de dades de signatures (Bloom + Hash JSON)
    let signature_db = match signatures::load_signatures() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("[-] Error crític carregant base de signatures: {}", e);
            return;
        }
    };

    // Inicialitzem el motor YARA
    let yara_engine = match yara_engine::YaraEngine::load() {
        Ok(engine) => engine,
        Err(e) => {
            eprintln!("[-] Error inicialitzant l'ecosistema YARA: {}", e);
            return;
        }
    };

    // Carreguem la configuració de l'usuari
    let config = match config::load_config() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("[-] No s'ha pogut llegir config.json: {}", e);
            return;
        }
    };

    println!("[*] Agent Asphylax actiu — signatures carregades, motor YARA inicialitzat.");
    println!("[*] Monitorització en temps real disponible via IPC (start_monitoring / subscribe_monitor_events).");

    // Arranquem el servidor IPC (bloquejant fins que el procés s'atura)
    if let Err(e) = communication::start_server(signature_db, yara_engine, config) {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            eprintln!("[-] L'agent ja sembla estar actiu a 127.0.0.1:7878. Atura la instancia anterior abans d'arrencar-ne una altra.");
        } else {
            eprintln!("[-] Error fatal al servei IPC: {}", e);
        }
    }
}
