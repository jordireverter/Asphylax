from app.services.agent_client import AgentClient


class HistoryController:
    def __init__(self):
        self.agent_client = AgentClient()

    def list_history(self) -> dict:
        return self.agent_client.list_history()