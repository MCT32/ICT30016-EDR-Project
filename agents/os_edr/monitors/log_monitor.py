import re
import time
from collections import defaultdict
from pathlib import Path
from alerting import AlertManager
from response import ResponseEngine


class LogMonitor:
    """Tails system logs and matches suspicious patterns.

    Patterns and thresholds are defined in config.yaml.
    Detects: SSH brute force, sudo abuse, user creation, su to root.
    """

    def __init__(self, config: dict, alert: AlertManager, responder: ResponseEngine):
        self.cfg = config["log_monitor"]
        self.alert = alert
        self.responder = responder
        self.file_positions: dict[str, int] = {}
        self.pattern_counts: dict[str, list[float]] = defaultdict(list)

    def _match_patterns(self, line: str, log_path: str):
        for pattern in self.cfg.get("patterns", []):
            regex = pattern["regex"]
            match = re.search(regex, line)
            if not match:
                continue

            name = pattern["name"]
            threshold = pattern.get("threshold", 1)
            window = pattern.get("threshold_window", 60)
            now = time.time()

            # Record detection time
            self.pattern_counts[name].append(now)

            # Keep only events within the window
            self.pattern_counts[name] = [
                t for t in self.pattern_counts[name] if now - t <= window
            ]

            if len(self.pattern_counts[name]) >= threshold:
                details = {"pattern": name, "log_file": log_path,
                           "matched_line": line.strip()}
                # Capture IP if present in the match
                if match.groups():
                    details["source_ip"] = match.group(1)

                self.responder.respond(
                    self.cfg["response_level"],
                    "log",
                    f"Log pattern triggered: {name} "
                    f"({len(self.pattern_counts[name])} events in {window}s)",
                    details,
                )
                self.pattern_counts[name].clear()

    def scan(self):
        for log_path in self.cfg.get("watched_logs", []):
            path = Path(log_path)
            if not path.exists():
                continue

            pos = self.file_positions.get(log_path, 0)
            current_size = path.stat().st_size

            if current_size < pos:
                pos = 0  # Log rotated

            with path.open("r", errors="replace") as f:
                f.seek(pos)
                for line in f:
                    self._match_patterns(line, log_path)
                self.file_positions[log_path] = f.tell()