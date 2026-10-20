import psutil
from alerting import AlertManager
from response import ResponseEngine


class NetworkMonitor:
    """Detects suspicious outbound network connections.

    Looks for:
    - Outbound connections to suspicious ports (common C2 / Metasploit)
    - Processes with excessive outbound connections
    """

    def __init__(self, config: dict, alert: AlertManager, responder: ResponseEngine):
        self.cfg = config["network_monitor"]
        self.alert = alert
        self.responder = responder
        self.allowed_ips = set(self.cfg.get("allowed_outbound_ips", []))
        self.alerted_ips: set[str] = set()

    def scan(self):
        conn_counts: dict[int, int] = {}

        for conn in psutil.net_connections(kind="inet"):
            if conn.status != psutil.CONN_ESTABLISHED:
                continue
            if not conn.raddr:
                continue

            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
            pid = conn.pid

            if not pid:
                continue

            # Skip allowed IPs
            if remote_ip in self.allowed_ips:
                continue

            # Check 1: suspicious outbound port
            if remote_port in self.cfg.get("suspicious_outbound_ports", []):
                key = f"{remote_ip}:{remote_port}"
                if key not in self.alerted_ips:
                    self.responder.respond(
                        self.cfg["response_level"],
                        "network",
                        f"Outbound connection to suspicious port "
                        f"{remote_ip}:{remote_port}",
                        {"pid": pid, "remote_ip": remote_ip,
                         "remote_port": remote_port},
                    )
                    self.alerted_ips.add(key)

            # Track connection count per process
            conn_counts[pid] = conn_counts.get(pid, 0) + 1

        # Check 2: excessive connections from a single process
        max_conns = self.cfg.get("max_connections_per_process", 50)
        for pid, count in conn_counts.items():
            if count > max_conns:
                try:
                    name = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    name = "unknown"
                self.responder.respond(
                    self.cfg["response_level"],
                    "network",
                    f"Process {name} has {count} outbound connections "
                    f"(threshold: {max_conns})",
                    {"pid": pid, "process_name": name, "connection_count": count},
                )