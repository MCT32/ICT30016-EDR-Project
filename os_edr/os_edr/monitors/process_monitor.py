import time
import psutil
from alerting import AlertManager
from response import ResponseEngine


class ProcessMonitor:
    """Detects suspicious process creation using psutil.

    Looks for:
    - Known-bad process names
    - Suspicious parent -> child relationships (e.g. nginx -> bash)
    - Processes listening on suspicious ports
    """

    def __init__(self, config: dict, alert: AlertManager, responder: ResponseEngine):
        self.cfg = config["process_monitor"]
        self.alert = alert
        self.responder = responder
        self.known_pids: set[int] = set()
        self.baseline_done = False
        self.baseline_start = time.time()

    def _snapshot_pids(self) -> set[int]:
        return {p.pid for p in psutil.process_iter(["pid"])}

    def _is_suspicious_parent(self, proc: psutil.Process) -> bool:
        try:
            parent = proc.parent()
            if parent and parent.name().lower() in [
                s.lower() for s in self.cfg.get("suspicious_parents", [])
            ]:
                child = proc.name().lower()
                if child in [s.lower() for s in self.cfg.get("suspicious_children", [])]:
                    return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return False

    def _is_known_bad(self, proc: psutil.Process) -> bool:
        name = proc.name().lower()
        return name in [s.lower() for s in self.cfg.get("known_bad_processes", [])]

    def _listening_on_suspicious_port(self, proc: psutil.Process) -> int | None:
        try:
            for conn in proc.connections(kind="inet"):
                if conn.status == psutil.CONN_LISTEN:
                    if conn.laddr.port in self.cfg.get("suspicious_ports", []):
                        return conn.laddr.port
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return None

    def scan(self):
        current_pids = self._snapshot_pids()
        new_pids = current_pids - self.known_pids

        # Baseline period: learn normal processes before alerting
        if not self.baseline_done:
            if time.time() - self.baseline_start < self.cfg.get(
                "baseline_period", 300
            ):
                self.known_pids = current_pids
                return
            self.baseline_done = True
            self.alert.info("[process] Baseline complete, monitoring active")

        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                name = proc.name()
                cmdline = " ".join(proc.cmdline() or [])
                parent_name = proc.parent().name() if proc.parent() else "?"

                # Check 1: known-bad process name
                if self._is_known_bad(proc):
                    self.responder.respond(
                        self.cfg["response_level"],
                        "process",
                        f"Known-bad process detected: {name}",
                        {"pid": pid, "process_name": name, "cmdline": cmdline},
                    )
                    continue

                # Check 2: suspicious parent -> child
                if self._is_suspicious_parent(proc):
                    self.responder.respond(
                        self.cfg["response_level"],
                        "process",
                        f"Suspicious child process: {parent_name} -> {name}",
                        {"pid": pid, "process_name": name,
                         "parent": parent_name, "cmdline": cmdline},
                    )
                    continue

                # Check 3: listening on suspicious port
                port = self._listening_on_suspicious_port(proc)
                if port:
                    self.responder.respond(
                        self.cfg["response_level"],
                        "process",
                        f"Process listening on suspicious port {port}: {name}",
                        {"pid": pid, "process_name": name, "port": port},
                    )

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        self.known_pids = current_pids