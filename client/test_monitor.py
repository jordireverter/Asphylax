import time

from app.monitoring.file_monitor import FileMonitor


monitor = FileMonitor()


def callback(path, action):
    print(f"[EVENT] {action}: {path}")


monitor.start("C:/Users/jordi/Asphylax/proves", callback)

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    monitor.stop()