import csv
import json
import os
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
import io
import zipfile
import gzip
import requests


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

SIGNATURES_FILE = DATA_DIR / "signatures.json"
STATE_FILE = DATA_DIR / "update_state.json"
TEMP_CSV_FILE = DATA_DIR / "malwarebazaar.csv"

UPDATE_INTERVAL_HOURS = 24
DEFAULT_NAME = "Imported.Signature"


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return now_utc().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def load_json_file(path: Path, default: Any) -> Any:
    if not path.exists():
        return default

    try:
        with path.open("r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return default
            return json.loads(content)
    except (json.JSONDecodeError, OSError):
        return default


def save_json_atomic(path: Path, data: Any) -> None:
    ensure_data_dir()
    with tempfile.NamedTemporaryFile(
        "w", delete=False, encoding="utf-8", dir=path.parent, suffix=".tmp"
    ) as tmp:
        json.dump(data, tmp, indent=2, ensure_ascii=False)
        tmp.flush()
        os.fsync(tmp.fileno())
        temp_name = tmp.name

    os.replace(temp_name, path)


def load_state() -> Dict[str, Any]:
    return load_json_file(
        STATE_FILE,
        {
            "last_successful_update": None,
            "last_attempt": None,
            "source": "malwarebazaar",
            "status": "never"
        },
    )


def save_state(state: Dict[str, Any]) -> None:
    save_json_atomic(STATE_FILE, state)


def load_existing_signatures() -> Dict[str, Any]:
    db = load_json_file(
        SIGNATURES_FILE,
        {
            "version": 1,
            "updated_at": now_iso(),
            "source": {"name": "custom", "type": "manual"},
            "entries": [],
        },
    )

    if isinstance(db, list):
        return {
            "version": 1,
            "updated_at": now_iso(),
            "source": {"name": "legacy", "type": "converted"},
            "entries": db,
        }

    if not isinstance(db, dict):
        return {
            "version": 1,
            "updated_at": now_iso(),
            "source": {"name": "custom", "type": "manual"},
            "entries": [],
        }

    if "entries" not in db:
        db["entries"] = []

    return db


def should_update(state: Dict[str, Any]) -> bool:
    last_success = state.get("last_successful_update")
    if not last_success:
        return True

    try:
        last_dt = datetime.fromisoformat(last_success.replace("Z", "+00:00"))
    except ValueError:
        return True

    return now_utc() - last_dt >= timedelta(hours=UPDATE_INTERVAL_HOURS)


def normalize_entry(
    hash_value: str,
    name: Optional[str] = None,
    family: Optional[str] = None,
    source: str = "unknown",
    severity: str = "high",
    confidence: int = 80,
    tags: Optional[List[str]] = None,
    first_seen: Optional[str] = None,
    last_seen: Optional[str] = None,
    reference: Optional[str] = None,
) -> Dict[str, Any]:
    hash_value = hash_value.strip().lower()
    tags = tags or []

    return {
        "id": f"sha256:{hash_value}",
        "name": name or DEFAULT_NAME,
        "family": family,
        "hash_type": "sha256",
        "hash_value": hash_value,
        "severity": severity,
        "confidence": confidence,
        "tags": tags,
        "source": source,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "reference": reference,
        "enabled": True,
    }


def upsert_entries(db: Dict[str, Any], new_entries: List[Dict[str, Any]]) -> int:
    existing = {
        entry["id"]: entry
        for entry in db.get("entries", [])
        if "id" in entry
    }

    changed = 0
    for entry in new_entries:
        entry_id = entry["id"]
        if existing.get(entry_id) != entry:
            existing[entry_id] = entry
            changed += 1

    db["entries"] = sorted(existing.values(), key=lambda e: e["id"])
    return changed


def validate_signatures_db(db: Dict[str, Any]) -> None:
    if "entries" not in db or not isinstance(db["entries"], list):
        raise ValueError("El fitxer de signatures no conté una llista 'entries' vàlida")

    for entry in db["entries"]:
        for field in ["id", "name", "hash_type", "hash_value", "source", "enabled"]:
            if field not in entry:
                raise ValueError(f"Falta el camp obligatori '{field}' en una entrada")

        if entry["hash_type"] != "sha256":
            raise ValueError("Només es permet hash_type='sha256' en aquesta versió")

        hash_value = entry["hash_value"]
        if not isinstance(hash_value, str) or len(hash_value) != 64:
            raise ValueError("S'ha trobat un hash SHA-256 invàlid")


def download_malwarebazaar_csv(auth_key: str, output_csv: Path) -> None:
    url = "https://bazaar.abuse.ch/export/csv/full/"
    headers = {
        "Auth-Key": auth_key,
        "User-Agent": "Asphylax/0.1",
    }

    response = requests.get(url, headers=headers, timeout=60)
    response.raise_for_status()
    output_csv.write_bytes(response.content)


def clean_csv_value(value: str) -> str:
    return value.strip().strip('"').strip()


def build_entries_from_csv(csv_path: Path) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []

    with open_csv_text(csv_path) as f:
        reader = csv.reader(f)

        for row in reader:
            if not row:
                continue

            if row[0].startswith("#"):
                continue

            # Format MalwareBazaar:
            # 0 first_seen
            # 1 sha256_hash
            # 2 md5_hash
            # 3 sha1_hash
            # 4 reporter
            # 5 file_name
            # 6 file_type_guess
            # 7 mime_type
            # 8 signature
            # ...
            if len(row) < 2:
                continue

            first_seen = clean_csv_value(row[0])
            sha256 = clean_csv_value(row[1]).lower()

            if len(sha256) != 64:
                continue

            file_name = clean_csv_value(row[5]) if len(row) > 5 else DEFAULT_NAME
            signature_name = clean_csv_value(row[8]) if len(row) > 8 else None

            if signature_name == "n/a" or not signature_name:
                signature_name = file_name or DEFAULT_NAME

            entry = normalize_entry(
                hash_value=sha256,
                name=signature_name,
                family=signature_name,
                source="malwarebazaar",
                tags=["imported", "hash", "malwarebazaar"],
                first_seen=first_seen,
                last_seen=None,
                reference=sha256,
            )

            entries.append(entry)

    print(f"Entrades llegides: {len(entries)}", flush=True)
    return entries

def open_csv_text(csv_path: Path):
    with csv_path.open("rb") as f:
        magic = f.read(4)

    if magic.startswith(b"PK"):
        zip_file = zipfile.ZipFile(csv_path)
        csv_names = [name for name in zip_file.namelist() if name.endswith(".csv")]

        if not csv_names:
            raise RuntimeError("El ZIP descarregat no conté cap fitxer CSV")

        return io.TextIOWrapper(
            zip_file.open(csv_names[0], "r"),
            encoding="utf-8",
            errors="replace",
            newline=""
        )

    if magic.startswith(b"\x1f\x8b"):
        return gzip.open(
            csv_path,
            "rt",
            encoding="utf-8",
            errors="replace",
            newline=""
        )

    return csv_path.open(
        "r",
        encoding="utf-8",
        errors="replace",
        newline=""
    )


def update_signatures() -> bool:
    ensure_data_dir()
    print("Llegint estat...", flush=True)
    state = load_state()

    print("Comprovant si toca actualitzar...", flush=True)

    if not should_update(state):
        print("No toca actualitzar encara.")
        return False

    state["last_attempt"] = now_iso()
    state["status"] = "running"
    save_state(state)

    auth_key = os.getenv("MALWAREBAZAAR_AUTH_KEY")
    if not auth_key:
        state["status"] = "error"
        save_state(state)
        raise RuntimeError("Falta MALWAREBAZAAR_AUTH_KEY")

    try:
        print("Descarregant CSV de MalwareBazaar...", flush=True)
        download_malwarebazaar_csv(auth_key, TEMP_CSV_FILE)

        db = load_existing_signatures()
        print("Construint signatures des del CSV...", flush=True)
        new_entries = build_entries_from_csv(TEMP_CSV_FILE)

        print(f"Entrades llegides: {len(new_entries)}", flush=True)
        changed = upsert_entries(db, new_entries)

        db["version"] = 1
        db["updated_at"] = now_iso()
        db["source"] = {
            "name": "malwarebazaar",
            "type": "automatic_import"
        }

        validate_signatures_db(db)
        save_json_atomic(SIGNATURES_FILE, db)

        state["last_successful_update"] = now_iso()
        state["status"] = "ok"
        save_state(state)

        print(f"Actualització completada. Entrades noves o actualitzades: {changed}")
        return True

    except Exception as exc:
        state["status"] = "error"
        save_state(state)
        raise exc


if __name__ == "__main__":
    updated = update_signatures()
    if updated:
        print("Base de signatures actualitzada.")
    else:
        print("Base de signatures ja estava al dia.")