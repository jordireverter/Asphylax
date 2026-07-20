import json
import socket
import threading


class AgentClient:
    def __init__(self, host="127.0.0.1", port=7878):
        self.host = host
        self.port = port

    def send_request(self, request: dict) -> dict:
        """Envia una comanda JSON a l'agent de Rust i retorna la resposta."""
        try:
            with socket.create_connection((self.host, self.port), timeout=300) as client:
                client.settimeout(300)
                message = json.dumps(request) + "\n"
                client.sendall(message.encode("utf-8"))

                with client.makefile("r", encoding="utf-8") as f:
                    line = f.readline()
                    if not line:
                        raise OSError("L'agent ha tancat el canal IPC abruptament.")
                    return json.loads(line.strip())

        except ConnectionRefusedError:
            return {
                "status": "error",
                "message": "No s'ha pogut connectar amb l'agent Asphylax. Comprova que el binari de Rust estigui en execució.",
                "data": None,
            }
        except socket.timeout:
            return {
                "status": "error",
                "message": "Temps d'espera (timeout) esgotat en el canal local.",
                "data": None,
            }
        except json.JSONDecodeError:
            return {
                "status": "error",
                "message": "Error de decodificació: la trama rebuda no conté un JSON vàlid.",
                "data": None,
            }
        except OSError as e:
            return {
                "status": "error",
                "message": f"Error del subsistema d'I/O local: {e}",
                "data": None,
            }

    # ── Accions bàsiques ──────────────────────────────────────────────────────

    def ping(self) -> dict:
        return self.send_request({"action": "ping"})

    def scan_path(self, path: str) -> dict:
        return self.send_request({"action": "scan", "path": path})

    def scan_path_stream(self, path: str, on_progress=None) -> dict:
        """Escaneig massiu amb callback de progrés en temps real."""
        try:
            with socket.create_connection((self.host, self.port), timeout=300) as client:
                client.settimeout(300)
                client.sendall((json.dumps({"action": "scan_progress", "path": path}) + "\n").encode("utf-8"))

                with client.makefile("r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        msg = json.loads(line)
                        if msg.get("type") == "progress" and on_progress:
                            on_progress(int(msg.get("percent", 0)))
                        elif msg.get("type") == "done":
                            return msg

                return {"status": "error", "message": "El canal IPC s'ha tancat sense confirmació final.", "data": None}

        except Exception as e:
            return {"status": "error", "message": f"Error al canal de progrés: {e}", "data": None}

    # ── Monitorització en temps real ──────────────────────────────────────────

    def start_agent_monitoring(self, path: str) -> dict:
        """Demana al nucli de Rust iniciar el monitor de disc."""
        return self.send_request({"action": "start_monitoring", "path": path})

    def stop_agent_monitoring(self) -> dict:
        """Demana al nucli de Rust aturar el monitor de disc."""
        return self.send_request({"action": "stop_monitoring"})

    def get_monitor_status(self) -> dict:
        """Retorna si el monitor de disc està actiu o no."""
        return self.send_request({"action": "get_monitor_status"})

    def subscribe_monitor_events(
        self,
        on_event,
        is_running_fn=None,
        on_stopped=None,
        on_error=None,
    ):
        """
        Manté una connexió de streaming oberta i crida `on_event(event_dict)` per
        cada detecció que el monitor detecti en temps real.

        Paràmetres:
            on_event(dict)       — cridat per cada event de tipus 'monitor_event'
            is_running_fn()      — funció que retorna False per tancar la subscripció
            on_stopped()         — cridat quan el monitor s'atura des de l'agent
            on_error(msg)        — cridat en cas d'error de connexió

        Disenyat per córrer en un fil de fons (daemon thread).
        """
        try:
            with socket.create_connection((self.host, self.port), timeout=None) as client:
                # Timeout llarg per als heartbeats (l'agent n'envia cada 5s)
                client.settimeout(30)

                # Sol·licitem la subscripció
                request = json.dumps({"action": "subscribe_monitor_events"}) + "\n"
                client.sendall(request.encode("utf-8"))

                with client.makefile("r", encoding="utf-8") as f:
                    for raw_line in f:
                        # Comprovem si el controlador ha demanat aturar la subscripció
                        if is_running_fn and not is_running_fn():
                            break

                        raw_line = raw_line.strip()
                        if not raw_line:
                            continue

                        try:
                            msg = json.loads(raw_line)
                        except json.JSONDecodeError:
                            continue

                        msg_type = msg.get("type", "")

                        if msg_type == "subscribed":
                            # Confirmació inicial de l'agent — ignorem o logem
                            pass

                        elif msg_type == "monitor_event":
                            # Event real de detecció → notifiquem la UI
                            event_data = msg.get("event", {})
                            if on_event:
                                # Passem els paràmetres que la UI espera (path, action)
                                on_event(event_data.get("path", ""), event_data.get("action", ""))

                        elif msg_type == "heartbeat":
                            # Pols de vida — ignorem, serveix per detectar desconnexions
                            pass

                        elif msg_type == "monitor_stopped":
                            # L'agent ha aturat el monitor explícitament
                            if on_stopped:
                                on_stopped()
                            break

                        elif msg_type == "error":
                            # Error retornat per l'agent (p.ex. cap monitor actiu)
                            if on_error:
                                on_error(msg.get("message", "Error desconegut"))
                            break

        except ConnectionRefusedError:
            if on_error:
                on_error("No s'ha pogut connectar amb l'agent Asphylax.")
        except socket.timeout:
            # Si el heartbeat no arriba en 30s, el considrem desconnectat
            if on_error:
                on_error("Timeout de heartbeat: l'agent pot haver-se aturat.")
        except OSError:
            # Connexió tancada inesperadament (normal si l'agent s'atura)
            pass
        except Exception as e:
            if on_error:
                on_error(f"Error inesperat al subscriptor d'events: {e}")

    # ── Quarantena ────────────────────────────────────────────────────────────

    def quarantine_file(self, path: str) -> dict:
        return self.send_request({"action": "quarantine", "path": path})

    def list_quarantine(self) -> dict:
        return self.send_request({"action": "list_quarantine"})

    def restore_quarantine(self, quarantine_id: str) -> dict:
        return self.send_request({"action": "restore_quarantine", "path": quarantine_id})

    def delete_quarantine(self, quarantine_id: str) -> dict:
        return self.send_request({"action": "delete_quarantine", "path": quarantine_id})

    # ── Historial ─────────────────────────────────────────────────────────────

    def list_history(self) -> dict:
        return self.send_request({"action": "list_history"})

    # ── Configuració ─────────────────────────────────────────────────────────

    def get_config(self) -> dict:
        return self.send_request({"action": "get_config"})

    def save_config(self, config: dict) -> dict:
        return self.send_request({"action": "save_config", "data": config})

    # ── Quick scan ────────────────────────────────────────────────────────────

    def quick_scan(self) -> dict:
        return self.send_request({"action": "quick_scan"})
