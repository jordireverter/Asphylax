import os
import time

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


SCAN_COOLDOWN_SECONDS = 2

IGNORED_EXTENSIONS = {
    ".tmp", ".lock", ".part", ".crdownload", ".swp"
}

IGNORED_PATH_PARTS = {
    "$RECYCLE.BIN",
    "System Volume Information",
}


class AsphylaxMonitorHandler(FileSystemEventHandler):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback
        self.last_scan_times = {}

    def path_exists_with_retry(self, path: str) -> bool:
        for _ in range(5):
            if os.path.exists(path):
                return True
            time.sleep(0.1)

        return False

    def should_ignore(self, path: str) -> bool:
        normalized = path.replace("/", "\\")

        for part in IGNORED_PATH_PARTS:
            if part.lower() in normalized.lower():
                print(f"[MONITOR] Ignorat per carpeta: {path}")
                return True

        _, extension = os.path.splitext(path)

        if extension.lower() in IGNORED_EXTENSIONS:
            print(f"[MONITOR] Ignorat per extensió: {path}")
            return True

        if not self.path_exists_with_retry(path):
            print(f"[MONITOR] Ignorat perquè ja no existeix: {path}")
            return True

        return False

    def should_scan(self, path: str) -> bool:
        if self.should_ignore(path):
            return False

        current_time = time.time()
        last_time = self.last_scan_times.get(path, 0)

        if current_time - last_time < SCAN_COOLDOWN_SECONDS:
            print(f"[MONITOR] Ignorat per cooldown: {path}")
            return False

        self.last_scan_times[path] = current_time
        return True

    def handle_file_event(self, path: str, action: str):
        print(f"[MONITOR] Event rebut: {action} -> {path}")

        if self.should_scan(path):
            print(f"[MONITOR] Escanejant: {path}")
            self.callback(path, action)

    def on_created(self, event):
        if event.is_directory:
            return

        self.handle_file_event(event.src_path, "created")

    def on_modified(self, event):
        if event.is_directory:
            return

        self.handle_file_event(event.src_path, "modified")

    def on_moved(self, event):
        if event.is_directory:
            return

        self.handle_file_event(event.dest_path, "moved")


class FileMonitor:
    def __init__(self):
        self.observer = None
        self.running = False

    def start(self, path, callback):
        if self.running:
            return

        event_handler = AsphylaxMonitorHandler(callback)

        self.observer = Observer()
        self.observer.schedule(event_handler, path, recursive=True)
        self.observer.start()

        self.running = True

        print(f"[MONITOR] Monitoritzant: {path}")

    def stop(self):
        if not self.running or not self.observer:
            return

        self.observer.stop()

        self.observer.join(timeout=1)

        self.running = False
        self.observer = None

        print("[MONITOR] Monitorització aturada")