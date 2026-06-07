use std::env;
use std::path::{Path, PathBuf};

pub fn project_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    candidate_roots(&manifest_dir)
        .into_iter()
        .find(|candidate| looks_like_project_root(candidate))
        .unwrap_or_else(|| manifest_dir.parent().unwrap_or(&manifest_dir).to_path_buf())
}

pub fn data_file(name: &str) -> PathBuf {
    project_root().join("data").join(name)
}

pub fn data_dir(name: &str) -> PathBuf {
    project_root().join("data").join(name)
}

pub fn history_dir() -> PathBuf {
    project_root().join("history")
}

pub fn history_file() -> PathBuf {
    history_dir().join("history.json")
}

pub fn quarantine_dir() -> PathBuf {
    project_root().join("quarantine")
}

pub fn quarantine_index_file() -> PathBuf {
    quarantine_dir().join("quarantine_index.json")
}

pub fn script_file(name: &str) -> PathBuf {
    project_root().join("scripts").join(name)
}

fn candidate_roots(manifest_dir: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(current_dir) = env::current_dir() {
        candidates.extend(ancestors_from(&current_dir));
    }

    if let Ok(current_exe) = env::current_exe() {
        if let Some(exe_dir) = current_exe.parent() {
            candidates.extend(ancestors_from(exe_dir));
        }
    }

    candidates.extend(ancestors_from(manifest_dir));

    candidates
}

fn ancestors_from(path: &Path) -> Vec<PathBuf> {
    path.ancestors().map(Path::to_path_buf).collect()
}

fn looks_like_project_root(path: &Path) -> bool {
    path.join("data").is_dir() && path.join("agent").join("Cargo.toml").is_file()
}
