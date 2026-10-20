import json
import logging
from datetime import datetime, timezone
from pathlib import Path


class AlertManager:
    """Shared alert format for the EDR suite.

    All monitors use this so alerts from the OS tool, XSS/SQLi tool,
    and DoS/DDoS tool can be merged into one log stream.
    """

    def __init__(self, alert_file: str = "/var/log/os_edr_alerts.log"):
        self.alert_file = Path(alert_file)
        self._setup_logging()

    def _setup_logging(self):
        self.logger = logging.getLogger("os_edr")
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler(self.alert_file)
        handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger.addHandler(handler)
        # Also print to console for debugging
        console = logging.StreamHandler()
        console.setFormatter(logging.Formatter("%(message)s"))
        self.logger.addHandler(console)

    def emit(self, monitor: str, level: int, message: str,
             details: dict | None = None):
        """Emit a structured alert in plain text (JSON line format).

        This matches the shared format so all EDR tools integrate.
        """
        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "monitor": monitor,          # process, file, network, log
            "response_level": level,
            "message": message,
            "details": details or {},
        }
        self.logger.info(json.dumps(alert))
        return alert

    def info(self, msg: str):
        self.logger.info(msg)

    def warning(self, msg: str):
        self.logger.warning(msg)

    def error(self, msg: str):
        self.logger.error(msg)