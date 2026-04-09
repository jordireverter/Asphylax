use std::fs;
use std::path::Path;

pub fn scan_path(path_str: &str) -> Result<String, String> {
    let path = Path::new(path_str);

    if !path.exists() {
        return Err("El path no existeix".to_string());
    }

    if path.is_file() {
        return Ok(format!("És un fitxer: {}", path_str));
    }

    if path.is_dir() {
        let entries = fs::read_dir(path)
            .map_err(|_| "No es pot llegir el directori")?;

        let count = entries.count();

        return Ok(format!(
            "És un directori amb {} elements",
            count
        ));
    }

    Err("Tipus de path desconegut".to_string())
}