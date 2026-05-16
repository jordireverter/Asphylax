from app.monitoring.file_monitor import FileMonitor
from app.services.agent_client import AgentClient


class MonitorController:
    def __init__(self):
        self.monitor = FileMonitor()
        self.agent_client = AgentClient()

    def start_monitoring(self, path: str, on_event):
        self.monitor.start(path, on_event)

    def stop_monitoring(self):
        self.monitor.stop()

    def scan_changed_file(self, path: str) -> dict:
        return self.agent_client.scan_path(path)