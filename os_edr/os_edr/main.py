import time
import yaml
import threading
from pathlib import Path

from alerting import AlertManager
from response import ResponseEngine
from monitors.process_monitor import ProcessMonitor
from monitors.file_monitor import FileMonitor
from monitors.network_monitor import NetworkMonitor
from monitors.log_monitor import LogMonitor


def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def main():
    config = load_config()
    alert = AlertManager(config["global"]["alert_file"])
    responder = ResponseEngine(config, alert)

    alert.info("=" * 60)
    alert.info("OS Attack Detection & Response — EDR Suite Module")
    alert.info("=" * 60)

    # Process monitor (polling thread)
    proc_monitor = ProcessMonitor(config, alert, responder)

    # File monitor (watchdog observer thread)
    file_monitor = FileMonitor(config, alert, responder)
    file_monitor.start()

    # Network monitor (polling thread)
    net_monitor = NetworkMonitor(config, alert, responder)

    # Log monitor (polling thread)
    log_monitor = LogMonitor(config, alert, responder)

    poll_interval = config["global"].get("poll_interval", 2)

    try:
        while True:
            if config["process_monitor"]["enabled"]:
                proc_monitor.scan()
            if config["network_monitor"]["enabled"]:
                net_monitor.scan()
            if config["log_monitor"]["enabled"]:
                log_monitor.scan()
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        alert.info("Shutting down...")
        file_monitor.stop()


if __name__ == "__main__":
    main()