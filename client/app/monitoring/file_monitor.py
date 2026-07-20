# La monitorització activa corre 100% en l'Agent de Rust (notify + escaneig reactiu).
# Aquest fitxer es manté com a passarel·la lleugera per no trencar l'arbre de control del Client.


class FileMonitor:
    def __init__(self):
        self.running = False

    def start(self, path: str, callback=None, excluded_paths=None, excluded_extensions=None):
        """Interfície abstracta. L'escolta real corre en l'espai de memòria de Rust."""
        self.running = True

    def stop(self):
        """Interfície abstracta."""
        self.running = False
