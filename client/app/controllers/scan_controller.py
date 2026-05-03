from app.services.agent_client import AgentClient


class ScanController:
    def __init__(self):
        self.agent_client = AgentClient()

    def scan(self, path: str) -> dict:
        if not path:
            return {
                "status": "error",
                "message": "No s'ha seleccionat cap ruta.",
                "data": None,
            }

        return self.agent_client.scan_path(path)
    

    def scan_stream(self, path: str, on_progress=None) -> dict:
        if not path:
            return {
                "status": "error",
                "message": "No s'ha seleccionat cap ruta.",
                "data": None,
            }

        return self.agent_client.scan_path_stream(path, on_progress)