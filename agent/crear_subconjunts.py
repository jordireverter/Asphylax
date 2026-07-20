"""
Crea els 5 subconjunts fixos (30, 75, 150, 225, 300 fitxers) a partir del
dataset sintètic complet, amb una llavor fixa perquè cada mida contingui
sempre exactament els mateixos fitxers entre execucions del benchmark.

Fa servir enllaços simbòlics (o còpia, si el sistema no ho permet) en comptes
de duplicar els 10MB de cada fitxer 5 vegades, per estalviar espai en disc.
"""

import os
import random
import shutil

DATASET_BASE = "dataset_sintetic"
OUTPUT_DIR = "datasets"
MIDES = [30, 75, 150, 225, 300]
SEED = 42


def crear_subconjunt(fitxers_ordenats: list[str], mida: int, usar_enllacos: bool) -> None:
    subset_dir = os.path.join(OUTPUT_DIR, f"mida_{mida}")
    os.makedirs(subset_dir, exist_ok=True)

    subset = fitxers_ordenats[:mida]

    for nom_fitxer in subset:
        origen = os.path.abspath(os.path.join(DATASET_BASE, nom_fitxer))
        desti = os.path.join(subset_dir, nom_fitxer)

        if os.path.exists(desti):
            continue

        if usar_enllacos:
            try:
                os.symlink(origen, desti)
                continue
            except OSError:
                # Sense privilegis per symlinks a Windows -> fallback a còpia
                usar_enllacos = False

        shutil.copy2(origen, desti)

    print(f"  Subconjunt de {mida} fitxers creat a '{subset_dir}/'")


def main() -> None:
    if not os.path.isdir(DATASET_BASE):
        raise SystemExit(
            f"No trobo '{DATASET_BASE}/'. Executa primer generar_dataset.py."
        )

    tots_fitxers = sorted(os.listdir(DATASET_BASE))
    if len(tots_fitxers) < max(MIDES):
        raise SystemExit(
            f"Nomes hi ha {len(tots_fitxers)} fitxers a '{DATASET_BASE}/', "
            f"calen almenys {max(MIDES)}."
        )

    # Llavor fixa: mateix ordre barrejat sempre -> subconjunts reproduïbles
    random.seed(SEED)
    random.shuffle(tots_fitxers)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Còpia real per defecte: fiable a Windows sense privilegis especials.
    # (Rust segueix symlinks correctament, però crear-los a Windows requereix
    # Mode Desenvolupador o ser administrador; no val la pena el risc.)
    usar_enllacos = False
    for mida in MIDES:
        crear_subconjunt(tots_fitxers, mida, usar_enllacos)

    print("\nFet. Subconjunts fixos creats a 'datasets/mida_{30,75,150,225,300}/'")


if __name__ == "__main__":
    main()
