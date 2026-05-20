from app.services.agent_client import AgentClient


class ConfigController:
    def __init__(self):
        self.agent_client = AgentClient()

    def get_config(self) -> dict:
        return self.agent_client.get_config()

    def save_config(self, config: dict) -> dict:
        return self.agent_client.save_config(config)