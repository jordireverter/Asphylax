"""
Orquestrador del benchmark de rendiment d'Asphylax.

Per cada combinacio de (nombre de threads) x (mida de dataset):
  1. Engega l'agent Rust amb RAYON_NUM_THREADS fixat
  2. Espera (via polling amb "ping") que el daemon estigui llest
  3. Fa REPETICIONS peticions de "scan" seguides, mesurant el temps de cada una
  4. Atura l'agent
Al final, desa totes les mesures a timing_results.csv

IMPORTANT: cal executar aquest script des del mateix directori on hi ha
l'executable de l'agent (agent.exe) i el seu config.json, o ajustar AGENT_EXE
amb la ruta completa.
"""

import csv
import json
import os
import signal
import socket
import subprocess
import sys
import time

AGENT_EXE = r".\target\release\asphylax_agent.exe"   # ajusta la ruta si cal
HOST, PORT = "127.0.0.1", 7878

THREADS = [1, 2, 4, 8]
MIDES = [30, 75, 150, 225, 300]
REPETICIONS = 8
DATASETS_DIR = "datasets"       # conté mida_30/, mida_75/, ... (creats amb crear_subconjunts.py)
CSV_SORTIDA = "timing_results.csv"


def engegar_agent(n_threads: int, timeout_ready: float = 30.0) -> subprocess.Popen:
    env = os.environ.copy()
    env["RAYON_NUM_THREADS"] = str(n_threads)

    proc = subprocess.Popen(
        [AGENT_EXE],
        env=env,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    inici_espera = time.time()
    while time.time() - inici_espera < timeout_ready:
        try:
            with socket.create_connection((HOST, PORT), timeout=1) as s:
                s.sendall((json.dumps({"action": "ping"}) + "\n").encode())
                with s.makefile("r", encoding="utf-8") as f:
                    if f.readline():
                        return proc
        except (ConnectionRefusedError, socket.timeout, OSError):
            time.sleep(0.3)

    proc.kill()
    proc.wait()
    raise RuntimeError(
        f"L'agent no ha respost en {timeout_ready}s (threads={n_threads})."
    )


def aturar_agent(proc: subprocess.Popen) -> None:
    proc.send_signal(signal.CTRL_BREAK_EVENT)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def enviar_scan(path: str) -> tuple[float, dict]:
    with socket.create_connection((HOST, PORT), timeout=300) as s:
        peticio = json.dumps({"action": "scan", "path": path}) + "\n"
        inici = time.perf_counter()
        s.sendall(peticio.encode())
        with s.makefile("r", encoding="utf-8") as f:
            line = f.readline()
        final = time.perf_counter()

    if not line:
        raise RuntimeError("L'agent ha tancat la connexio sense respondre.")

    resposta = json.loads(line.strip())
    return final - inici, resposta


def executar_test(n_threads: int, dataset_path: str, repeticions: int) -> list[float]:
    proc = engegar_agent(n_threads)
    temps_llista = []
    try:
        for rep in range(repeticions):
            temps, resposta = enviar_scan(dataset_path)
            n_fitxers = len(resposta.get("data", {}).get("files", []))
            status = resposta.get("status", "?")
            print(
                f"  threads={n_threads:<2} rep={rep+1}/{repeticions} "
                f"temps={temps:7.3f}s status={status} fitxers_amb_deteccio={n_fitxers}"
            )
            temps_llista.append(temps)
    finally:
        aturar_agent(proc)
    return temps_llista


def main() -> None:
    if not os.path.isdir(DATASETS_DIR):
        raise SystemExit(
            f"No trobo '{DATASETS_DIR}/'. Executa primer crear_subconjunts.py."
        )

    resultats = []
    total_combinacions = len(THREADS) * len(MIDES)
    combinacio_actual = 0

    for n_threads in THREADS:
        for mida in MIDES:
            combinacio_actual += 1
            subset_dir = os.path.abspath(os.path.join(DATASETS_DIR, f"mida_{mida}"))

            if not os.path.isdir(subset_dir):
                print(f"AVIS: no existeix {subset_dir}, salto aquesta combinacio.")
                continue

            print(
                f"\n[{combinacio_actual}/{total_combinacions}] "
                f"threads={n_threads} mida={mida} -> {subset_dir}"
            )
            temps_llista = executar_test(n_threads, subset_dir, REPETICIONS)

            for rep, t in enumerate(temps_llista):
                resultats.append([n_threads, mida, rep, t])

    with open(CSV_SORTIDA, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["threads", "mida_dataset", "repeticio", "temps_segons"])
        writer.writerows(resultats)

    print(f"\nFet. {len(resultats)} mesures desades a '{CSV_SORTIDA}'")


if __name__ == "__main__":
    main()
