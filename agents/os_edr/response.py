import os
import shutil
import subprocess
from pathlib import Path
from alerting import AlertManager


class ResponseEngine:
    """Execute response actions based on configured levels.

    Level 1 (Monitor): log only
    Level 2 (Alert):   log + notify
    Level 3 (Contain): log + kill process, block IP, quarantine file
    Level 4 (Lockdown): Level 3 + block all outbound traffic
    """

    def __init__(self, config: dict, alert_manager: AlertManager):
        self.config = config
        self.alert = alert_manager
        self.quarantine_dir = Path("/var/quarantine/os_edr")
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.blocked_ips: set[str] = set()

    # ------------------------------------------------------------------
    # Process actions
    # ------------------------------------------------------------------
    def kill_process(self, pid: int, name: str) -> bool:
        """Terminate a process gracefully, then forcefully."""
        try:
            os.kill(pid, 15)  # SIGTERM
            self.alert.info(f"[response] Sent SIGTERM to {name} (pid={pid})")
            return True
        except ProcessLookupError:
            self.alert.warning(f"[response] Process {pid} no longer exists")
            return False
        except PermissionError:
            self.alert.error(f"[response] Permission denied killing {pid}")
            return False

    def kill_process_force(self, pid: int, name: str) -> bool:
        """Force kill if graceful termination fails."""
        try:
            os.kill(pid, 9)  # SIGKILL
            self.alert.info(f"[response] Sent SIGKILL to {name} (pid={pid})")
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            self.alert.error(f"[response] Permission denied force-killing {pid}")
            return False

    # ------------------------------------------------------------------
    # Network actions
    # ------------------------------------------------------------------
    def block_ip(self, ip: str, duration: int = 300) -> bool:
        """Block an outbound IP using iptables for a set duration."""
        if ip in self.blocked_ips:
            return True
        try:
            subprocess.run(
                ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
                check=True, capture_output=True, timeout=10,
            )
            self.blocked_ips.add(ip)
            self.alert.info(f"[response] Blocked outbound IP {ip} for {duration}s")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            self.alert.error(f"[response] Failed to block {ip}: {e}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        """Remove an iptables block rule."""
        try:
            subprocess.run(
                ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
                check=True, capture_output=True, timeout=10,
            )
            self.blocked_ips.discard(ip)
            self.alert.info(f"[response] Unblocked IP {ip}")
            return True
        except subprocess.CalledProcessError:
            return False

    def lockdown_host(self) -> bool:
        """Level 4: block all outbound traffic except loopback."""
        try:
            subprocess.run(
                ["iptables", "-A", "OUTPUT", "!", "-o", "lo", "-j", "DROP"],
                check=True, capture_output=True, timeout=10,
            )
            self.alert.warning("[response] LOCKDOWN: all outbound traffic blocked")
            return True
        except subprocess.CalledProcessError:
            return False

    # ------------------------------------------------------------------
    # File actions
    # ------------------------------------------------------------------
    def quarantine_file(self, filepath: str) -> bool:
        """Move a suspicious file to quarantine, preserving metadata."""
        src = Path(filepath)
        if not src.exists():
            return False
        dest = self.quarantine_dir / f"{src.name}_{int(src.stat().st_mtime)}"
        try:
            shutil.move(str(src), str(dest))
            self.alert.info(f"[response] Quarantined {filepath} -> {dest}")
            return True
        except (shutil.Error, PermissionError) as e:
            self.alert.error(f"[response] Quarantine failed for {filepath}: {e}")
            return False

    # ------------------------------------------------------------------
    # Level dispatcher
    # ------------------------------------------------------------------
    def respond(self, level: int, monitor: str, message: str,
                details: dict | None = None):
        """Execute the response level for a detection.

        Level 1: log only
        Level 2: log (alert already emitted)
        Level 3: contain (kill/block/quarantine)
        Level 4: lockdown
        """
        self.alert.emit(monitor, level, message, details)

        if level < 3:
            return  # Monitor or Alert: no system change

        if level == 3 and details:
            pid = details.get("pid")
            ip = details.get("remote_ip")
            filepath = details.get("filepath")

            if pid:
                self.kill_process_force(pid, details.get("process_name", "unknown"))
            if ip:
                self.block_ip(ip, self.config["network_monitor"].get("block_duration", 300))
            if filepath:
                self.quarantine_file(filepath)

        if level >= 4:
            self.lockdown_host()