import os
import re
import json
import time
import ipaddress
import subprocess
from collections import defaultdict, deque
from datetime import datetime, timezone

AGENT_NAME = "authentication"

AUTH_LOG = "/var/log/auth.log"
ALERT_FILE = "auth_alerts.jsonl"
STATE_FILE = "auth_state.json"

FAILED_LOGIN_THRESHOLD = 5
FAILED_LOGIN_WINDOW = 60 * 60

RAPID_FAILURE_THRESHOLD = 5
RAPID_FAILURE_WINDOW = 30

FIRST_BLOCK_DURATION = 60 * 60
REPEAT_BLOCK_DURATION = 24 * 60 * 60

ENUMERATION_USERNAME_THRESHOLD = 5
ENUMERATION_WINDOW = 10 * 60

ACCOUNT_REVIEW_THRESHOLD = 2

SUDO_FAILURE_THRESHOLD = 3
SUDO_FAILURE_WINDOW = 10 * 60

TRUSTED_IPS = {
    "127.0.0.1",
    "::1"
}

failed_by_account = defaultdict(deque)
failed_by_ip = defaultdict(deque)
invalid_users_by_ip = defaultdict(deque)
sudo_failures = defaultdict(deque)

ip_lockout_history = defaultdict(int)
account_attack_history = defaultdict(int)

blocked_ips = {}


def utc_timestamp():
    return datetime.now(timezone.utc).isoformat()


def readable_duration(seconds):
    if seconds >= 86400:
        return f"{int(seconds / 86400)} day(s)"

    if seconds >= 3600:
        return f"{int(seconds / 3600)} hour(s)"

    if seconds >= 60:
        return f"{int(seconds / 60)} minute(s)"

    return f"{seconds} second(s)"


def write_alert(
    event,
    severity,
    message,
    source_ip=None,
    username=None,
    attempts=None,
    action=None,
    extra=None

):
    alert = {
        "agent": AGENT_NAME,
        "event": event,
        "severity": severity.upper(),
        "timestamp": utc_timestamp(),
        "message": message
    }

    if source_ip is not None:
        alert["source_ip"] = source_ip

    if username is not None:
        alert["username"] = username

    if attempts is not None:
        alert["attempts"] = attempts

    if action is not None:
        alert["action"] = action

    if extra is not None:
        alert.update(extra)

    print()
    print("=" * 70)
    print(f"[{alert['severity']}] {alert['event']}")
    print(json.dumps(alert, indent=2))
    print("=" * 70)
    print()

    try:
        with open(ALERT_FILE, "a") as file:
            file.write(json.dumps(alert) + "\n")

    except Exception as error:
        print(f"[ERROR] Could not write alert file: {error}")


def save_state():
    state = {
        "blocked_ips": blocked_ips,
        "ip_lockout_history": dict(ip_lockout_history),
        "account_attack_history": dict(account_attack_history)
    }

    try:
        with open(STATE_FILE, "w") as file:
            json.dump(state, file, indent=2)

    except Exception as error:
        print(f"[ERROR] Could not save state: {error}")


def load_state():
    global blocked_ips

    if not os.path.exists(STATE_FILE):
        return

    try:
        with open(STATE_FILE, "r") as file:
            state = json.load(file)

        blocked_ips = state.get("blocked_ips", {})

        for ip, count in state.get("ip_lockout_history", {}).items():
            ip_lockout_history[ip] = count

        for username, count in state.get("account_attack_history", {}).items():
            account_attack_history[username] = count

    except Exception as error:
        print(f"[WARNING] Could not load previous state: {error}")


def safe_to_block(ip):
    if ip in TRUSTED_IPS:
        print(f"[INFO] {ip} is trusted. Automatic block skipped.")
        return False

    try:
        address = ipaddress.ip_address(ip)

        if address.is_loopback:
            return False

        if address.is_multicast:
            return False

        if address.is_unspecified:
            return False

        return True

    except ValueError:
        return False


def firewall_rule_exists(ip):
    result = subprocess.run(
        [
            "iptables",
            "-C",
            "INPUT",
            "-s",
            ip,
            "-p",
            "tcp",
            "--dport",
            "22",
            "-j",
            "DROP"
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return result.returncode == 0


def add_firewall_block(ip):
    if not safe_to_block(ip):
        return False

    try:
        if firewall_rule_exists(ip):
            return True

        subprocess.run(
            [
                "iptables",
                "-I",
                "INPUT",
                "-s",
                ip,
                "-p",
                "tcp",
                "--dport",
                "22",
                "-j",
                "DROP"
            ],
            check=True
        )

        return True

    except FileNotFoundError:
        print("[ERROR] iptables command is not available.")
        return False

    except subprocess.CalledProcessError as error:
        print(f"[ERROR] Firewall failed to block {ip}: {error}")
        return False


def remove_firewall_block(ip):
    try:
        while firewall_rule_exists(ip):
            subprocess.run(
                [
                    "iptables",
                    "-D",
                    "INPUT",
                    "-s",
                    ip,
                    "-p",
                    "tcp",
                    "--dport",
                    "22",
                    "-j",
                    "DROP"
                ],
                check=False
            )

        return True

    except Exception as error:
        print(f"[ERROR] Could not remove firewall block for {ip}: {error}")
        return False


def blacklist_ip(ip, reason, username=None):
    if ip in blocked_ips:
        expiry = blocked_ips[ip]["expires"]

        if time.time() < expiry:
            return False

    ip_lockout_history[ip] += 1
    offence_count = ip_lockout_history[ip]

    if offence_count == 1:
        duration = FIRST_BLOCK_DURATION
    else:
        duration = REPEAT_BLOCK_DURATION

    if not add_firewall_block(ip):
        write_alert(
            event="blacklist_failed",
            severity="CRITICAL",
            message="Authentication attack detected but automatic IP blocking failed.",
            source_ip=ip,
            username=username,
            action="Administrator investigation required"
        )

        save_state()
        return False

    expiry = time.time() + duration

    blocked_ips[ip] = {
        "expires": expiry,
        "reason": reason,
        "duration": duration
    }

    save_state()

    write_alert(
        event="ip_blacklisted",
        severity="HIGH",
        message="Suspicious authentication source was added to the SSH IP blacklist.",
        source_ip=ip,
        username=username,
        action=f"SSH blocked for {readable_duration(duration)}",
        extra={
            "offence_number": offence_count,
            "reason": reason,
            "block_expires": datetime.fromtimestamp(
                expiry,
                timezone.utc
            ).isoformat()
        }
    )

    return True


def check_expired_blacklist():
    now = time.time()
    expired = []

    for ip, information in blocked_ips.items():
        if now >= information["expires"]:
            expired.append(ip)

    for ip in expired:
        remove_firewall_block(ip)
        blocked_ips.pop(ip, None)

        write_alert(
            event="ip_blacklist_expired",
            severity="INFO",
            message="Temporary authentication blacklist entry expired.",
            source_ip=ip,
            action="SSH access restored"
        )

        save_state()


def restore_blacklist():
    now = time.time()
    expired = []

    for ip, information in blocked_ips.items():
        if now >= information["expires"]:
            expired.append(ip)
        else:
            add_firewall_block(ip)
            print(f"[EDR] Restored active blacklist: {ip}")

    for ip in expired:
        remove_firewall_block(ip)
        blocked_ips.pop(ip, None)

    save_state()


def remove_old_timestamps(queue, window):
    now = time.time()

    while queue:
        if now - queue[0] > window:
            queue.popleft()
        else:
            break


def handle_invalid_user(ip, username):
    now = time.time()
    queue = invalid_users_by_ip[ip]

    queue.append((now, username))

    while queue:
        timestamp, old_username = queue[0]

        if now - timestamp > ENUMERATION_WINDOW:
            queue.popleft()
        else:
            break

    unique_users = {
        attempted_username
        for timestamp, attempted_username in queue
    }

    write_alert(
        event="invalid_user_attempt",
        severity="MEDIUM",
        message="Authentication attempt used a non-existent account.",
        source_ip=ip,
        username=username,
        action="Monitoring"
    )

    if len(unique_users) >= ENUMERATION_USERNAME_THRESHOLD:
        write_alert(
            event="account_enumeration",
            severity="HIGH",
            message="Possible account enumeration detected.",
            source_ip=ip,
            attempts=len(unique_users),
            action="Source will be temporarily blacklisted",
            extra={
                "invalid_usernames": sorted(unique_users)
            }
        )

        blacklist_ip(
            ip,
            reason="Account enumeration"
        )

        queue.clear()


def handle_failed_login(ip, username):
    now = time.time()

    account_key = (ip, username)

    account_queue = failed_by_account[account_key]
    ip_queue = failed_by_ip[ip]

    account_queue.append(now)
    ip_queue.append(now)

    remove_old_timestamps(
        account_queue,
        FAILED_LOGIN_WINDOW
    )

    remove_old_timestamps(
        ip_queue,
        RAPID_FAILURE_WINDOW
    )

    account_count = len(account_queue)
    rapid_count = len(ip_queue)

    if account_count < FAILED_LOGIN_THRESHOLD:
        write_alert(
            event="failed_login",
            severity="LOW",
            message="Failed authentication attempt detected.",
            source_ip=ip,
            username=username,
            attempts=account_count,
            action="Monitoring"
        )

    if (
        rapid_count >= RAPID_FAILURE_THRESHOLD
        and ip not in blocked_ips
    ):
        account_attack_history[username] += 1

        write_alert(
            event="rapid_brute_force",
            severity="HIGH",
            message=(
                f"{rapid_count} failed authentication attempts "
                f"occurred within {RAPID_FAILURE_WINDOW} seconds."
            ),
            source_ip=ip,
            username=username,
            attempts=rapid_count,
            action="Automatic IP blacklist"
        )

        check_account_attack_history(
            username,
            ip
        )

        blacklist_ip(
            ip,
            reason="Rapid brute-force authentication attack",
            username=username
        )

        account_queue.clear()
        ip_queue.clear()

        return

    if (
        account_count >= FAILED_LOGIN_THRESHOLD
        and ip not in blocked_ips
    ):
        account_attack_history[username] += 1

        write_alert(
            event="brute_force_attack",
            severity="HIGH",
            message=(
                f"{account_count} failed login attempts "
                f"were detected against the same account within one hour."
            ),
            source_ip=ip,
            username=username,
            attempts=account_count,
            action="Automatic IP blacklist"
        )

        check_account_attack_history(
            username,
            ip
        )

        blacklist_ip(
            ip,
            reason="Repeated failed authentication",
            username=username
        )

        account_queue.clear()
        ip_queue.clear()


def check_account_attack_history(username, source_ip):
    count = account_attack_history[username]

    if count >= ACCOUNT_REVIEW_THRESHOLD:
        write_alert(
            event="repeated_account_targeting",
            severity="CRITICAL",
            message=(
                "The same account has been targeted during "
                "multiple authentication attacks."
            ),
            source_ip=source_ip,
            username=username,
            attempts=count,
            action="Account flagged for administrator review",
            extra={
                "attack_incidents": count
            }
        )

        save_state()


def handle_successful_login(ip, username):
    key = (ip, username)

    queue = failed_by_account[key]

    remove_old_timestamps(
        queue,
        FAILED_LOGIN_WINDOW
    )

    previous_failures = len(queue)

    if previous_failures >= 3:
        write_alert(
            event="successful_login_after_failures",
            severity="CRITICAL",
            message="Authentication succeeded after several failed login attempts.",
            source_ip=ip,
            username=username,
            attempts=previous_failures,
            action="Administrator investigation recommended"
        )
    else:
        write_alert(
            event="successful_login",
            severity="INFO",
            message="Successful SSH authentication detected.",
            source_ip=ip,
            username=username,
            action="No automatic response"
        )

    queue.clear()


def extract_sudo_username(line):
    match = re.search(
        r"user=(\S+)",
        line
    )

    if match:
        return match.group(1)

    match = re.search(
        r"ruser=(\S+)",
        line
    )

    if match:
        return match.group(1)

    return "unknown"


def handle_sudo_failure(line):
    username = extract_sudo_username(line)

    queue = sudo_failures[username]

    queue.append(time.time())

    remove_old_timestamps(
        queue,
        SUDO_FAILURE_WINDOW
    )

    count = len(queue)

    write_alert(
        event="sudo_authentication_failure",
        severity="MEDIUM",
        message="Failed sudo authentication detected.",
        username=username,
        attempts=count,
        action="Monitoring privileged access"
    )

    if count >= SUDO_FAILURE_THRESHOLD:
        write_alert(
            event="repeated_sudo_failures",
            severity="HIGH",
            message="Multiple failed attempts to obtain elevated privileges were detected.",
            username=username,
            attempts=count,
            action="Administrator investigation recommended"
        )

        queue.clear()


def handle_sudo_command(line):
    match = re.search(
        r"sudo:\s+(\S+)\s+:\s+.*COMMAND=(.*)$",
        line
    )

    if not match:
        return

    username = match.group(1)
    command = match.group(2).strip()

    write_alert(
        event="privileged_command",
        severity="INFO",
        message="A command was executed using sudo.",
        username=username,
        action="Privileged activity recorded",
        extra={
            "command": command
        }
    )


def process_log_line(line):
    failed_match = re.search(
        r"Failed password for "
        r"(?:invalid user )?"
        r"(\S+) from "
        r"([0-9a-fA-F:.]+)",
        line
    )

    if failed_match:
        username = failed_match.group(1)
        source_ip = failed_match.group(2)

        handle_failed_login(
            source_ip,
            username
        )

        return

    invalid_match = re.search(
        r"Invalid user "
        r"(\S+) from "
        r"([0-9a-fA-F:.]+)",
        line
    )

    if invalid_match:
        username = invalid_match.group(1)
        source_ip = invalid_match.group(2)

        handle_invalid_user(
            source_ip,
            username
        )

        return

    success_match = re.search(
        r"Accepted "
        r"(?:password|publickey) "
        r"for (\S+) from "
        r"([0-9a-fA-F:.]+)",
        line
    )

    if success_match:
        username = success_match.group(1)
        source_ip = success_match.group(2)

        handle_successful_login(
            source_ip,
            username
        )

        return

    if (
        "sudo:auth" in line
        and "authentication failure" in line
    ):
        handle_sudo_failure(line)
        return

    if (
        "sudo:" in line
        and "COMMAND=" in line
    ):
        handle_sudo_command(line)
        return


def monitor_auth_log():
    print(f"[EDR] Monitoring {AUTH_LOG}")

    with open(
        AUTH_LOG,
        "r",
        errors="replace"
    ) as logfile:

        logfile.seek(
            0,
            os.SEEK_END
        )

        while True:
            check_expired_blacklist()

            line = logfile.readline()

            if not line:
                time.sleep(0.2)
                continue

            process_log_line(line)


def monitor_journal():
    print("[EDR] /var/log/auth.log not found.")
    print("[EDR] Falling back to system journal.")

    process = subprocess.Popen(
        [
            "journalctl",
            "-f",
            "-n",
            "0",
            "-o",
            "cat"
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    if process.stdout is None:
        raise RuntimeError(
            "Unable to monitor system journal."
        )

    while True:
        check_expired_blacklist()

        line = process.stdout.readline()

        if not line:
            time.sleep(0.2)
            continue

        process_log_line(line)


def display_banner():
    print()
    print("=" * 70)
    print("EDR AUTHENTICATION AGENT")
    print("=" * 70)
    print()
    print("Authentication monitoring started.")
    print()


def main():
    display_banner()

    if os.geteuid() != 0:
        print("[ERROR] Authentication agent must run as root.")
        print()
        print("Run:")
        print("sudo python3 auth_agent.py")
        print()
        return

    load_state()
    restore_blacklist()

    print(f"[EDR] Alert file: {ALERT_FILE}")
    print(f"[EDR] State file: {STATE_FILE}")
    print()
    print("[EDR] Authentication agent started.")
    print("[EDR] Press Ctrl+C to stop.")
    print()

    try:
        if os.path.exists(AUTH_LOG):
            monitor_auth_log()
        else:
            monitor_journal()

    except KeyboardInterrupt:
        print()
        print("[EDR] Authentication agent stopped.")
        save_state()

    except PermissionError:
        print("[ERROR] Permission denied while reading authentication data.")
        print("Run using:")
        print("sudo python3 auth_agent.py")

    except Exception as error:
        print(f"[ERROR] Unexpected agent error: {error}")
        save_state()


if __name__ == "__main__":
    main()


