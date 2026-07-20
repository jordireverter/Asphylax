"""
Genera el dataset sintètic per a l'anàlisi de rendiment d'escaneig d'Asphylax.

Crea N_FITXERS fitxers de MIDA_MB cadascun, amb contingut mitjanament variat
(blocs alternant patrons repetitius d'entropia baixa i blocs aleatoris d'entropia
alta), per simular de forma aproximada l'estructura d'un binari real sense
dependre de malware/goodware reals.

El contingut NO importa per aquest anàlisi (només rendiment/temps), però es
busca una entropia "realista" perquè el pipeline de l'agent (hash, YARA,
anàlisi PE/heurística) treballi de manera representativa.
"""

import os
import random

OUTPUT_DIR = "dataset_sintetic"
N_FITXERS = 300
MIDA_MB = 10
MIDA_BYTES = MIDA_MB * 1024 * 1024
BLOC = 4096  # mida de cada bloc dins el fitxer


def generar_bloc_variat(seed_bloc: int) -> bytes:
    """Alterna blocs aleatoris amb blocs de patró repetitiu per variar l'entropia."""
    random.seed(seed_bloc)
    if seed_bloc % 3 == 0:
        # bloc repetitiu (baixa entropia, simula seccions .data/.rodata)
        patro = bytes([random.randint(0, 255) for _ in range(16)])
        return (patro * (BLOC // len(patro) + 1))[:BLOC]
    else:
        # bloc aleatori (alta entropia, simula .text compilat o seccions comprimides)
        return os.urandom(BLOC)


def generar_fitxer(path: str, mida_bytes: int, seed_base: int) -> None:
    n_blocs = mida_bytes // BLOC
    resta = mida_bytes % BLOC
    with open(path, "wb") as f:
        for b in range(n_blocs):
            f.write(generar_bloc_variat(seed_base + b))
        if resta:
            f.write(os.urandom(resta))


def main() -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    for i in range(N_FITXERS):
        path = os.path.join(OUTPUT_DIR, f"sample_{i:03d}.bin")
        generar_fitxer(path, MIDA_BYTES, seed_base=i * 100000)
        if (i + 1) % 25 == 0 or i == N_FITXERS - 1:
            print(f"  {i + 1}/{N_FITXERS} fitxers generats...")

    mida_total_gb = (N_FITXERS * MIDA_MB) / 1024
    print(f"\nFet. {N_FITXERS} fitxers de {MIDA_MB} MB a '{OUTPUT_DIR}/'")
    print(f"Mida total del dataset: {mida_total_gb:.2f} GB")


if __name__ == "__main__":
    main()
