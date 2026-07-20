import csv
import shutil
import subprocess
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
AGENT_DIR = BASE_DIR / "agent"

SOURCE_DIR = BASE_DIR / "data" / "yara_rules" / "imported"
VALID_DIR = BASE_DIR / "data" / "yara_rules_validated" / "imported"
BAD_DIR = BASE_DIR / "data" / "yara_rules_disabled"

REPORT_FILE = BASE_DIR / "data" / "yara_validation_report.csv"

VALIDATOR_EXE = AGENT_DIR / "target" / "debug" / "yara_rule_validator.exe"

TIMEOUT_SECONDS = 10


def find_yara_files(directory: Path):
    return sorted(
        list(directory.rglob("*.yar")) + list(directory.rglob("*.yara"))
    )


def validate_rule(rule_path: Path):
    try:
        result = subprocess.run(
            [str(VALIDATOR_EXE), str(rule_path)],
            cwd=AGENT_DIR,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
        )

        if result.returncode == 0:
            return "ok", result.stdout.strip()

        return "error", (result.stderr or result.stdout).strip()

    except subprocess.TimeoutExpired:
        return "timeout", "La regla ha superat el temps màxim"

    except Exception as exc:
        return "error", str(exc)


def copy_rule(rule_path: Path, destination_base: Path):
    relative = rule_path.relative_to(SOURCE_DIR)
    destination = destination_base / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(rule_path, destination)


def main():
    if not VALIDATOR_EXE.exists():
        raise RuntimeError(
            f"No existeix {VALIDATOR_EXE}. Executa abans: cargo build --bin yara_rule_validator"
        )

    VALID_DIR.mkdir(parents=True, exist_ok=True)
    BAD_DIR.mkdir(parents=True, exist_ok=True)

    rules = find_yara_files(SOURCE_DIR)

    print(f"Regles trobades: {len(rules)}")

    ok_count = 0
    bad_count = 0

    with REPORT_FILE.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["rule", "status", "details"])

        for index, rule in enumerate(rules, start=1):
            print(f"[{index}/{len(rules)}] Validant {rule.name}...")

            status, details = validate_rule(rule)

            writer.writerow([str(rule), status, details])

            if status == "ok":
                copy_rule(rule, VALID_DIR)
                ok_count += 1
            else:
                copy_rule(rule, BAD_DIR)
                bad_count += 1
                print(f"  DESCARTADA: {status} - {details[:150]}")

    print()
    print(f"Validació acabada.")
    print(f"Regles compatibles: {ok_count}")
    print(f"Regles descartades: {bad_count}")
    print(f"Informe: {REPORT_FILE}")


if __name__ == "__main__":
    main()