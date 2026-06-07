import threading
from app.monitoring.file_monitor import FileMonitor
from app.services.agent_client import AgentClient


class MonitorController:
    """
    Controlador de la monitorització en temps real.

    Arquitectura:
        1. `start_monitoring` envia `start_monitoring` a l'agent de Rust via IPC.
        2. Immediatament després, arrenca un fil de fons que es connecta a l'agent
           via `subscribe_monitor_events` i rep un stream JSON persistent.
        3. Per cada detecció, el fil crida el callback `on_event` de la UI (PyQt).
        4. `stop_monitoring` envia `stop_monitoring` a l'agent, cosa que tanca el
           canal i fa acabar naturalment el fil de fons.
    """

    def __init__(self):
        self.monitor        = FileMonitor()
        self.agent_client   = AgentClient()
        self._running       = False
        self._sub_thread: threading.Thread | None = None
        self._on_event      = None
        self._on_stopped    = None

    # ── API pública ───────────────────────────────────────────────────────────

    def start_monitoring(
        self,
        path: str,
        on_event=None,
        on_stopped=None,
        on_error=None,
        excluded_paths=None,
        excluded_extensions=None,
    ) -> dict:
        """
        Inicia la monitorització al directori `path`.

        Paràmetres:
            on_event(dict)   — cridat des del fil de fons per cada detecció
            on_stopped()     — cridat quan l'agent atura el monitor per si sol
            on_error(msg)    — cridat en cas d'error de connexió del subscriptor
        """
        if self._running:
            return {"status": "error", "message": "El monitor ja està actiu."}

        # 1. Demanem a l'agent iniciar el monitor de disc
        result = self.agent_client.start_agent_monitoring(path)
        if result.get("status") != "ok":
            return result

        # 2. Actualitzem l'estat del stub local
        self.monitor.start(path)
        self._running    = True
        self._on_event   = on_event
        self._on_stopped = on_stopped

        # 3. Arranquem el fil de subscripció d'events en segon pla
        if on_event is not None:
            self._sub_thread = threading.Thread(
                target=self._run_event_subscriber,
                args=(on_event, on_stopped, on_error),
                daemon=True,  # S'atura automàticament si el procés principal acaba
                name="AsphylaxMonitorSubscriber",
            )
            self._sub_thread.start()

        return result

    def stop_monitoring(self) -> dict:
        """
        Atura la monitorització.

        El fil de fons acabarà sol quan l'agent tanqui el canal (Sender destruït).
        """
        if not self._running:
            return {"status": "ok", "message": "El monitor ja estava aturat."}

        self._running = False
        self.monitor.stop()

        # Demanem a l'agent aturar el monitor (tanca el canal → acaba el fil)
        result = self.agent_client.stop_agent_monitoring()

        # Esperem que el fil de subscripció s'aturi (màxim 3s per no bloquejar la UI)
        if self._sub_thread and self._sub_thread.is_alive():
            self._sub_thread.join(timeout=3.0)
        self._sub_thread = None

        return result

    def is_running(self) -> bool:
        return self._running

    def get_monitor_status(self) -> dict:
        """Consulta l'estat real del monitor a l'agent."""
        return self.agent_client.get_monitor_status()

    def scan_changed_file(self, path: str) -> dict:
        """Escaneig puntual d'un fitxer (per ús manual des de la UI)."""
        return self.agent_client.scan_path(path)

    # ── Fil de fons ───────────────────────────────────────────────────────────

    def _run_event_subscriber(self, on_event, on_stopped, on_error):
        """
        Fil de fons: manté la connexió de streaming amb l'agent i reenvia
        els events de detecció cap als callbacks de la UI.

        El bucle intern de `subscribe_monitor_events` s'acaba quan:
          - `is_running_fn()` retorna False (l'usuari ha demanat aturar).
          - L'agent tanca el canal (monitor aturat des de Rust).
          - Error de connexió.
        """
        def _on_stopped_wrapper():
            self._running = False
            self.monitor.stop()
            if on_stopped:
                on_stopped()

        self.agent_client.subscribe_monitor_events(
            on_event=on_event,
            is_running_fn=lambda: self._running,
            on_stopped=_on_stopped_wrapper,
            on_error=on_error,
        )
