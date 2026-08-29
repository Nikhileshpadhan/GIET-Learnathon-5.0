import os
import sys
import subprocess
import datetime
from collections import defaultdict
from config import (
    DRY_RUN,
    SAFE_WHITELIST,
    THREAT_THRESHOLD,
    ACTIONS_LOG_PATH,
    BLOCKED_IPS_PATH,
    NGINX_DENY_PATH
)

class AutomatedIPBlocker:
    """
    Automated Infrastructure-Level IP Blocker with Safety Controls:
    - Configurable Whitelist Protection
    - Dry-Run Safe Mode
    - Nginx Blocklist configuration generator
    - OS Firewall Integration (Linux iptables/ufw & Windows netsh)
    """

    def __init__(self):
        self.threat_scores = defaultdict(float)
        self.blocked_ips = set()
        self._load_existing_blocks()

    def _load_existing_blocks(self):
        if BLOCKED_IPS_PATH.exists():
            try:
                with open(BLOCKED_IPS_PATH, "r", encoding="utf-8") as f:
                    for line in f:
                        ip = line.strip()
                        if ip and not ip.startswith("#"):
                            self.blocked_ips.add(ip)
            except Exception as e:
                print(f"[Blocker] Error reading existing blocked IPs: {e}")

    def is_whitelisted(self, ip: str) -> bool:
        """Checks whether an IP is in the safe whitelist."""
        if ip in SAFE_WHITELIST:
            return True
        for safe in SAFE_WHITELIST:
            if safe.startswith(ip) or ip.startswith(safe):
                return True
        return False

    def record_threat(self, ip: str, score: float, reason: str):
        """Accumulates threat score and executes blocking if threshold is breached."""
        if self.is_whitelisted(ip):
            return

        self.threat_scores[ip] += score
        current_score = self.threat_scores[ip]

        now = datetime.datetime.utcnow().isoformat()
        log_entry = f"[{now}] [THREAT_DETECTED] IP: {ip} | Added Score: +{score:.1f} | Total Score: {current_score:.1f}/{THREAT_THRESHOLD} | Reason: {reason}\n"
        self._append_action_log(log_entry)
        print(log_entry.strip())

        if current_score >= THREAT_THRESHOLD and ip not in self.blocked_ips:
            self.execute_block(ip, reason)

    def execute_block(self, ip: str, reason: str):
        """Applies blocking at the infrastructure level with Dry-Run safeguards."""
        if self.is_whitelisted(ip):
            print(f"[Blocker] Safeguard: Refusing to block whitelisted IP {ip}")
            return

        self.blocked_ips.add(ip)
        now = datetime.datetime.utcnow().isoformat()

        if DRY_RUN:
            action_msg = f"[{now}] [DRY_RUN_BLOCK] WOULD BLOCK IP: {ip} | Score: {self.threat_scores[ip]:.1f} | Reason: {reason}\n"
            print(f"\033[93m{action_msg.strip()}\033[0m")
            self._append_action_log(action_msg)
            self._append_blocked_ip(ip, f"DRY_RUN: {reason}")
            return

        # LIVE BLOCKING MODE
        action_msg = f"[{now}] [LIVE_BLOCK] BLOCKING IP AT INFRASTRUCTURE: {ip} | Reason: {reason}\n"
        print(f"\033[91m{action_msg.strip()}\033[0m")
        self._append_action_log(action_msg)
        self._append_blocked_ip(ip, reason)

        # 1. Update Nginx Deny List
        self._update_nginx_blocklist(ip)

        # 2. Trigger OS-level firewall rule
        self._apply_os_firewall_rule(ip)

    def _append_action_log(self, text: str):
        try:
            with open(ACTIONS_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(text)
        except Exception:
            pass

    def _append_blocked_ip(self, ip: str, comment: str):
        try:
            with open(BLOCKED_IPS_PATH, "a", encoding="utf-8") as f:
                f.write(f"{ip} # {comment}\n")
        except Exception:
            pass

    def _update_nginx_blocklist(self, ip: str):
        """Appends deny rule to Nginx blockips configuration file."""
        try:
            with open(NGINX_DENY_PATH, "a", encoding="utf-8") as f:
                f.write(f"deny {ip};\n")
        except Exception as e:
            print(f"[Blocker] Failed to update Nginx deny list: {e}")

    def _apply_os_firewall_rule(self, ip: str):
        """Applies OS-level firewall drop rule (Linux ufw/iptables, Windows netsh)."""
        try:
            if sys.platform.startswith("linux"):
                # Try UFW first, then iptables
                res = subprocess.run(["ufw", "deny", "from", ip], capture_output=True, text=True)
                if res.returncode != 0:
                    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
                print(f"[Blocker] Linux firewall rule added for IP {ip}")
            elif sys.platform == "win32":
                rule_name = f"HG_Block_{ip.replace(':', '_')}"
                cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"]
                subprocess.run(cmd, capture_output=True)
                print(f"[Blocker] Windows firewall rule added for IP {ip}")
        except Exception as e:
            print(f"[Blocker] OS firewall execution note ({e}) - Nginx and app blocklists remain active.")
