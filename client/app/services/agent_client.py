import json
import socket


class AgentClient:
    def __init__(self, host="127.0.0.1", port=7878):
        self.host = host
        self.port = port

    def send_request(self, request: dict) -> dict:
        try:
            with socket.create_connection((self.host, self.port), timeout=300) as client:
                client.settimeout(300)

                message = json.dumps(request) + "\n"
                client.sendall(message.encode("utf-8"))

                response = self._read_line(client)
                return json.loads(response)

        except ConnectionRefusedError:
            return {
                "status": "error",
                "message": "No s'ha pogut connectar amb l'agent. Comprova que Rust està executant-se.",
                "data": None,
            }
        except socket.timeout:
            return {
                "status": "error",
                "message": "Temps d'espera esgotat connectant amb l'agent.",
                "data": None,
            }
        except json.JSONDecodeError:
            return {
                "status": "error",
                "message": "La resposta de l'agent no és JSON vàlid.",
                "data": None,
            }
        except OSError as error:
            return {
                "status": "error",
                "message": f"Error de comunicació amb l'agent: {error}",
                "data": None,
            }

    def scan_path(self, path: str) -> dict:
        return self.send_request({
            "action": "scan",
            "path": path,
        })

    def ping(self) -> dict:
        return self.send_request({
            "action": "ping",
        })

    def _read_line(self, client: socket.socket) -> str:
        chunks = []

        while True:
            chunk = client.recv(4096)
            if not chunk:
                break

            chunks.append(chunk)

            if b"\n" in chunk:
                break

        return b"".join(chunks).decode("utf-8").strip()
    

    def scan_path_stream(self, path: str, on_progress=None) -> dict:
        try:
            with socket.create_connection((self.host, self.port), timeout=300) as client:
                client.settimeout(300)

                request = {
                    "action": "scan_progress",
                    "path": path,
                }

                message = json.dumps(request) + "\n"
                client.sendall(message.encode("utf-8"))

                file = client.makefile("r", encoding="utf-8")

                for line in file:
                    if not line.strip():
                        continue

                    response = json.loads(line)

                    if response.get("type") == "progress":
                        if on_progress:
                            on_progress(int(response.get("percent", 0)))

                    elif response.get("type") == "done":
                        return response

                return {
                    "status": "error",
                    "message": "Connexió tancada sense resposta final.",
                    "data": None,
                }

        except Exception as error:
            return {
                "status": "error",
                "message": f"Error comunicant amb l'agent: {error}",
                "data": None,
            }
        
    
    def quarantine_file(self, path: str) -> dict:
        return self.send_request({
            "action": "quarantine",
            "path": path,
        })
    
    def list_quarantine(self) -> dict:
        return self.send_request({
            "action": "list_quarantine",
        })
    

    def restore_quarantine(self, quarantine_id: str) -> dict:
        return self.send_request({
            "action": "restore_quarantine",
            "path": quarantine_id,
        })
    

    def delete_quarantine(self, quarantine_id: str) -> dict:
        return self.send_request({
            "action": "delete_quarantine",
            "path": quarantine_id,
        })
    

    def list_history(self) -> dict:
        return self.send_request({
            "action": "list_history",
        })
    

    def get_config(self) -> dict:
        return self.send_request({
            "action": "get_config",
        })

    def save_config(self, config: dict) -> dict:
        return self.send_request({
            "action": "save_config",
            "data": config,
        })