import hashlib
import time
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from alerting import AlertManager
from response import ResponseEngine


class IntegrityHandler(FileSystemEventHandler):
    """Watchdog handler for file integrity monitoring."""

    def __init__(self, cfg: dict, alert: AlertManager, responder: ResponseEngine):
        self.cfg = cfg
        self.alert = alert
        self.responder = responder

    def _should_ignore(self, path: str) -> bool:
        import fnmatch
        return any(
            fnmatch.fnmatch(path, pat)
            for pat in self.cfg.get("ignore_patterns", [])
        )

    def on_modified(self, event):
        if event.is_directory or self._should_ignore(event.src_path):
            return
        self.responder.respond(
            self.cfg["response_level"],
            "file",
            f"Modified: {event.src_path}",
            {"filepath": event.src_path, "event": "modified"},
        )

    def on_created(self, event):
        if event.is_directory or self._should_ignore(event.src_path):
            return
        self.responder.respond(
            self.cfg["response_level"],
            "file",
            f"Created: {event.src_path}",
            {"filepath": event.src_path, "event": "created"},
        )

    def on_deleted(self, event):
        if event.is_directory or self._should_ignore(event.src_path):
            return
        self.responder.respond(
            self.cfg["response_level"],
            "file",
            f"Deleted: {event.src_path}",
            {"filepath": event.src_path, "event": "deleted"},
        )


class FileMonitor:
    """Monitors critical files and directories for changes."""

    def __init__(self, config: dict, alert: AlertManager, responder: ResponseEngine):
        self.cfg = config["file_monitor"]
        self.alert = alert
        self.responder = responder
        self.observer = Observer()

    def start(self):
        handler = IntegrityHandler(self.cfg, self.alert, self.responder)
        for path in self.cfg.get("watched_paths", []):
            p = Path(path)
            if p.exists():
                watch_dir = str(p.parent) if p.is_file() else str(p)
                self.observer.schedule(handler, watch_dir, recursive=True)
                self.alert.info(f"[file] Watching {watch_dir}")
        self.observer.start()
        self.alert.info("[file] File integrity monitor started")

    def stop(self):
        self.observer.stop()
        self.observer.join()