import os
import time

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


SCAN_COOLDOWN_SECONDS = 2


class AsphylaxMonitorHandler(FileSystemEventHandler):
    def __init__(self, callback, excluded_paths=None, excluded_extensions=None):
        super().__init__()

        self.callback = callback
        self.last_scan_times = {}
        self.excluded_paths = excluded_paths or []
        self.excluded_extensions = excluded_extensions or []

    def normalize_path(self, path: str) -> str:
        return path.replace("\\", "/").lower()

    def path_exists_with_retry(self, path: str) -> bool:
        for _ in range(5):
            if os.path.exists(path):
                return True
            time.sleep(0.1)

        return False

    def should_ignore(self, path: str) -> bool:
        normalized = self.normalize_path(path)

        for excluded_path in self.excluded_paths:
            excluded = self.normalize_path(excluded_path)

            if normalized.startswith(excluded):
                return True

        _, extension = os.path.splitext(path)

        if extension.lower() in [ext.lower() for ext in self.excluded_extensions]:
            return True

        if not self.path_exists_with_retry(path):
            return True

        return False

    def should_scan(self, path: str) -> bool:
        if self.should_ignore(path):
            return False

        current_time = time.time()
        last_time = self.last_scan_times.get(path, 0)

        if current_time - last_time < SCAN_COOLDOWN_SECONDS:
            return False

        self.last_scan_times[path] = current_time
        return True

    def handle_file_event(self, path: str, action: str):
        if self.should_scan(path):
            self.callback(path, action)

    def on_created(self, event):
        if not event.is_directory:
            self.handle_file_event(event.src_path, "created")

    def on_modified(self, event):
        if not event.is_directory:
            self.handle_file_event(event.src_path, "modified")

    def on_moved(self, event):
        if not event.is_directory:
            self.handle_file_event(event.dest_path, "moved")


class FileMonitor:
    def __init__(self):
        self.observer = None
        self.running = False

    def start(self, path, callback, excluded_paths=None, excluded_extensions=None):
        if self.running:
            return

        event_handler = AsphylaxMonitorHandler(
            callback,
            excluded_paths=excluded_paths,
            excluded_extensions=excluded_extensions,
        )

        self.observer = Observer()
        self.observer.schedule(event_handler, path, recursive=True)
        self.observer.start()

        self.running = True

    def stop(self):
        if not self.running or not self.observer:
            return

        self.observer.stop()
        self.observer.join(timeout=1)

        self.running = False
        self.observer = None