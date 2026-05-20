from app.services.agent_client import AgentClient


class QuarantineController:
    def __init__(self):
        self.agent_client = AgentClient()

    def quarantine_file(self, path: str) -> dict:
        if not path:
            return {
                "status": "error",
                "message": "No s'ha seleccionat cap fitxer.",
                "data": None,
            }

        return self.agent_client.quarantine_file(path)

    def list_quarantine(self) -> dict:
        return self.agent_client.list_quarantine()
    


    def restore_quarantine(self, quarantine_id: str) -> dict:
        return self.agent_client.restore_quarantine(quarantine_id)
    

    def delete_quarantine(self, quarantine_id: str) -> dict:
        return self.agent_client.delete_quarantine(quarantine_id)