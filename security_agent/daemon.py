import asyncio
import json
import os
import signal
import sys
import time
from pathlib import Path

from config import (
    ACCESS_LOG_PATH,
    DRY_RUN,
    SAFE_WHITELIST,
    THREAT_THRESHOLD,
    SQLI_SCORE,
    XSS_SCORE,
    PATH_TRAVERSAL_SCORE,
    BEHAVIORAL_ANOMALY_SCORE,
    HIGH_ERROR_RATE_SCORE
)
from detector_supervised import SupervisedAttackDetector
from detector_unsupervised import UnsupervisedAnomalyDetector
from blocker import AutomatedIPBlocker

running = True

def handle_exit(signum, frame):
    global running
    print("\n[Daemon] Graceful shutdown requested...")
    running = False

signal.signal(signal.SIGINT, handle_exit)
signal.signal(signal.SIGTERM, handle_exit)

async def tail_log_file(file_path: Path):
    """Asynchronously tails an append-only JSON Lines access log file."""
    while not file_path.exists():
        print(f"[Daemon] Waiting for access log file to be created at {file_path}...")
        await asyncio.sleep(2)

    with open(file_path, "r", encoding="utf-8") as f:
        # Seek to the end of existing lines on fresh startup
        f.seek(0, os.SEEK_END)

        while running:
            line = f.readline()
            if not line:
                await asyncio.sleep(0.2)
                continue

            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
                yield event
            except json.JSONDecodeError:
                continue

async def main():
    print("=" * 60)
    print("  HostelGrievance ML Security Monitoring & IP-Blocking Daemon")
    print("=" * 60)
    print(f"  Mode: {'DRY RUN (Safe / Logging only)' if DRY_RUN else 'LIVE ENFORCEMENT'}")
    print(f"  Log Source: {ACCESS_LOG_PATH}")
    print(f"  Threat Threshold: {THREAT_THRESHOLD}")
    print(f"  Whitelisted IPs: {', '.join(sorted(list(SAFE_WHITELIST)))}")
    print("=" * 60)

    supervised_detector = SupervisedAttackDetector()
    unsupervised_detector = UnsupervisedAnomalyDetector()
    blocker = AutomatedIPBlocker()

    print("[Daemon] Security Agent is listening for real-time web telemetry...\n")

    async for event in tail_log_file(ACCESS_LOG_PATH):
        if not running:
            break

        client_ip = event.get("ip", "127.0.0.1")
        method = event.get("method", "GET")
        path = event.get("path", "/")
        status = int(event.get("status", 200))

        # 1. Feed event to unsupervised behavioral tracker
        unsupervised_detector.record_event(event)

        # 2. Supervised Payload Attack Detection (NLP / Heuristic)
        is_attack, attack_type, confidence = supervised_detector.analyze_event(event)
        if is_attack:
            score = SQLI_SCORE if "sqli" in attack_type else (XSS_SCORE if "xss" in attack_type else PATH_TRAVERSAL_SCORE)
            reason = f"Supervised {attack_type.upper()} Attack in {method} {path} (conf: {confidence:.2f})"
            blocker.record_threat(client_ip, score, reason)

        # 3. Unsupervised Behavioral Anomaly Scoring (IsolationForest)
        is_anomaly, anomaly_score, anomaly_reason = unsupervised_detector.score_ip(client_ip)
        if is_anomaly:
            score = BEHAVIORAL_ANOMALY_SCORE * anomaly_score
            reason = f"Unsupervised Anomaly: {anomaly_reason}"
            blocker.record_threat(client_ip, score, reason)

        # 4. Immediate high error rate scoring
        if status >= 400 and not blocker.is_whitelisted(client_ip):
            blocker.record_threat(client_ip, 0.5, f"HTTP {status} on {path}")

    print("[Daemon] Security daemon stopped cleanly.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
