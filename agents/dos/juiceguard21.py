#!/usr/bin/env python3

"""
JuiceGuard v2.1 for ICT30016 Project

Host-based DoS/DDoS protection.

Features:
- VM-wide TCP monitoring
- Spike detection
- Temporary IP blocking
- Permanent repeat-offender blocking
- Automatic unblocking
- CSV logging
- Allowlist support
- Dedicated iptables chain
- Desktop notifications (not working yet)
- Email Notification (not yet included, future version)
"""

import os
import csv
import time
import subprocess

from collections import defaultdict, deque
from datetime import datetime

# #########################
# STARTUP DIRECTORY CHECK
# ########################

os.makedirs(
    "/opt/edr/dos",
    exist_ok=True
)

# ##############
# CONFIGURATION
# #############

BLOCK_TIME = 600

RULE_1_SEC = 15
RULE_10_SEC = 50
RULE_60_SEC = 300
RULE_5_MIN = 1000

CHAIN_NAME = "JUICEGUARD"

CSV_FILE = (
    "/opt/edr/dos/blocked_ips.csv"
)

ALLOWLIST_FILE = (
    "/opt/edr/dos/allowlist.txt"
)

PERMANENT_BLOCKLIST_FILE = (
    "/opt/edr/dos/permanent_blocklist.txt"
)

PERMANENT_BLOCK_THRESHOLD = 5
PERMANENT_WINDOW = 86400

# ###############
# DATA STRUCTURES
# ################

request_history = defaultdict(deque)

active_blocks = {}

offender_history = defaultdict(deque)

# ###############
# LOAD ALLOWLIST
# ###############

def load_allowlist():

    if not os.path.exists(
        ALLOWLIST_FILE
    ):
        return set()

    with open(
        ALLOWLIST_FILE,
        "r"
    ) as file:

        return {
            line.strip()
            for line in file
            if line.strip()
        }

ALLOWLIST = load_allowlist()

# ##########
# GUI ALERTS
# ##########

def show_popup_alert(ip, reason):

    try:

        subprocess.run(
            [
                "notify-send",
                "JuiceGuard Alert",
                f"Blocked IP: {ip}\nReason: {reason}"
            ],
            check=False
        )

    except Exception as error:

        print(
            f"[WARNING] Notification failed: {error}",
            flush=True
        )

# ####################
# IPTABLES CHAIN SETUP
# ####################

def setup_chain():

    try:

        chain_check = subprocess.run(
            [
                "iptables",
                "-L",
                CHAIN_NAME
            ],
            capture_output=True
        )

        if chain_check.returncode != 0:

            print(
                f"[INIT] Creating chain {CHAIN_NAME}",
                flush=True
            )

            subprocess.run(
                [
                    "iptables",
                    "-N",
                    CHAIN_NAME
                ],
                check=False
            )

        jump_check = subprocess.run(
            [
                "iptables",
                "-C",
                "INPUT",
                "-j",
                CHAIN_NAME
            ],
            capture_output=True
        )

        if jump_check.returncode != 0:

            print(
                "[INIT] Linking INPUT to JUICEGUARD",
                flush=True
            )

            subprocess.run(
                [
                    "iptables",
                    "-I",
                    "INPUT",
                    "-j",
                    CHAIN_NAME
                ],
                check=False
            )

    except Exception as error:

        print(
            f"[ERROR] Chain setup failed: {error}",
            flush=True
        )

# #############
# CSV LOGGING
# ###########

def log_event(
    ip,
    reason,
    action,
    offence_count=0
):

    file_exists = os.path.isfile(
        CSV_FILE
    )

    with open(
        CSV_FILE,
        "a",
        newline=""
    ) as csvfile:

        writer = csv.writer(csvfile)

        if not file_exists:

            writer.writerow([
                "timestamp",
                "ip",
                "reason",
                "action",
                "offence_count"
            ])

        writer.writerow([
            datetime.utcnow().isoformat(),
            ip,
            reason,
            action,
            offence_count
        ])

# ################
# OFFENCE TRACKING
# ################

def record_offence(ip):

    now = time.time()

    offender_history[ip].append(now)

    cutoff = now - PERMANENT_WINDOW

    while (
        offender_history[ip]
        and offender_history[ip][0] < cutoff
    ):
        offender_history[ip].popleft()

    return len(
        offender_history[ip]
    )

# ###################
# PERMANENT BLOCKING
# ##################

def permanent_block(ip):

    existing = set()

    if os.path.exists(
        PERMANENT_BLOCKLIST_FILE
    ):

        with open(
            PERMANENT_BLOCKLIST_FILE,
            "r"
        ) as file:

            existing = {
                line.strip()
                for line in file
                if line.strip()
            }

    if ip in existing:
        return

    print(
        f"[PERMANENT BLOCK] {ip}",
        flush=True
    )

    subprocess.run(
        [
            "iptables",
            "-I",
            CHAIN_NAME,
            "-s",
            ip,
            "-j",
            "DROP"
        ],
        check=False
    )

    with open(
        PERMANENT_BLOCKLIST_FILE,
        "a"
    ) as file:

        file.write(f"{ip}\n")

    log_event(
        ip,
        "PERMANENT_BLOCK",
        "BLOCK"
    )

#    show_popup_alert(
#        ip,
#        "PERMANENT_BLOCK"
#    )

# ########################
# LOAD PERMANENT BLOCKLIST
# ########################

def load_permanent_blocklist():

    if not os.path.exists(
        PERMANENT_BLOCKLIST_FILE
    ):
        return

    with open(
        PERMANENT_BLOCKLIST_FILE,
        "r"
    ) as file:

        for ip in file:

            ip = ip.strip()

            if not ip:
                continue

            subprocess.run(
                [
                    "iptables",
                    "-I",
                    CHAIN_NAME,
                    "-s",
                    ip,
                    "-j",
                    "DROP"
                ],
                check=False
            )

# ##################
# BLOCKING FUNCTIONS
# ###################

def block_ip(ip, reason):

    if ip in active_blocks:
        return

    offence_count = record_offence(ip)

    if (
        offence_count >=
        PERMANENT_BLOCK_THRESHOLD
    ):

        permanent_block(ip)

        return

    subprocess.run(
        [
            "iptables",
            "-I",
            CHAIN_NAME,
            "-s",
            ip,
            "-j",
            "DROP"
        ],
        check=False
    )

    active_blocks[ip] = time.time()

    print(
        f"[BLOCK] {ip} ({reason})",
        flush=True
    )

    log_event(
        ip,
        reason,
        "BLOCK",
        offence_count
    )

#    show_popup_alert(
#        ip,
#        reason
#    )

def unblock_ip(ip):

    subprocess.run(
        [
            "iptables",
            "-D",
            CHAIN_NAME,
            "-s",
            ip,
            "-j",
            "DROP"
        ],
        check=False
    )

    print(
        f"[UNBLOCK] {ip}",
        flush=True
    )

    log_event(
        ip,
        "",
        "UNBLOCK"
    )

def cleanup_expired_blocks():

    now = time.time()

    expired = []

    for ip, block_time in active_blocks.items():

        if (
            now - block_time >
            BLOCK_TIME
        ):
            expired.append(ip)

    for ip in expired:

        unblock_ip(ip)

        del active_blocks[ip]

# ###################
# CONNECTION ANALYSIS
# ###################

def process_connection(ip):

    if ip in ALLOWLIST:
        return

    now = time.time()

    requests = request_history[ip]

    requests.append(now)

    cutoff = now - 300

    while (
        requests
        and requests[0] < cutoff
    ):
        requests.popleft()

    count_1 = sum(
        1 for x in requests
        if x > now - 1
    )

    count_10 = sum(
        1 for x in requests
        if x > now - 10
    )

    count_60 = sum(
        1 for x in requests
        if x > now - 60
    )

    count_300 = len(requests)

    reason = None

    if count_1 > RULE_1_SEC:

        reason = "15_CONN_1_SEC"

    elif count_10 > RULE_10_SEC:

        reason = "50_CONN_10_SEC"

    elif count_60 > RULE_60_SEC:

        reason = "300_CONN_60_SEC"

    elif count_300 > RULE_5_MIN:

        reason = "1000_CONN_5_MIN"

    if reason:

        block_ip(
            ip,
            reason
        )

# ##################
# CONNECTION MONITOR
# ##################

def capture_connections():

    try:

        result = subprocess.run(
            [
                "ss",
                "-ant"
            ],
            capture_output=True,
            text=True
        )

        connection_counts = {}

        for line in result.stdout.splitlines():

            if (
                "ESTAB" not in line
                and "SYN-RECV" not in line
                and "TIME-WAIT" not in line
                and "CLOSE-WAIT" not in line
            ):
                continue

            parts = line.split()

            if len(parts) < 5:
                continue

            remote = parts[-1]

            try:

                ip = remote.rsplit(
                    ":",
                    1
                )[0]

                ip = ip.strip("[]")

                if ip.startswith("::ffff:"):

                    ip = ip.replace(
                        "::ffff:",
                        ""
                    )

                if (
                    ip.startswith("127.")
                    or ip == "::1"
                ):
                    continue

                connection_counts[ip] = (
                    connection_counts.get(
                        ip,
                        0
                    ) + 1
                )

            except Exception:
                pass

        return connection_counts

    except Exception as error:

        print(
            f"[ERROR] capture_connections: {error}",
            flush=True
        )

        return {}

# #####
# MAIN
# #####

def main():

    print(
        "JuiceGuard Host Protection starting...",
        flush=True
    )

    setup_chain()

    load_permanent_blocklist()

    while True:

        try:

            cleanup_expired_blocks()

            connections = capture_connections()

            for ip, count in connections.items():

                for _ in range(count):

                    process_connection(ip)

            time.sleep(1)

        except KeyboardInterrupt:

            print(
                "JuiceGuard stopped.",
                flush=True
            )

            break

        except Exception as error:

            print(
                f"[ERROR] {error}",
                flush=True
            )

            time.sleep(5)

if __name__ == "__main__":
    main()
