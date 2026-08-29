import os
from pathlib import Path

# Paths
AGENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = AGENT_DIR.parent
LOGS_DIR = PROJECT_ROOT / "logs"

# Ensure logs directory exists
LOGS_DIR.mkdir(parents=True, exist_ok=True)

ACCESS_LOG_PATH = LOGS_DIR / "access.jsonl"
ACTIONS_LOG_PATH = LOGS_DIR / "security_actions.log"
BLOCKED_IPS_PATH = LOGS_DIR / "blocked_ips.txt"
NGINX_DENY_PATH = LOGS_DIR / "nginx_blockips.conf"

# Safety Controls
# DRY_RUN = True by default: logs all intended actions without modifying system firewall
DRY_RUN = os.getenv("SECURITY_DRY_RUN", "true").lower() in ("true", "1", "yes")

# Safe IP Whitelist (never blocked under any circumstances)
SAFE_WHITELIST = {
    "127.0.0.1",
    "::1",
    "localhost",
    "0.0.0.0",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
}

# Add any custom safe IP from environment
CUSTOM_SAFE_IPS = os.getenv("SAFE_IPS", "")
if CUSTOM_SAFE_IPS:
    for ip in CUSTOM_SAFE_IPS.split(","):
        cleaned = ip.trim() if hasattr(ip, 'trim') else ip.strip()
        if cleaned:
            SAFE_WHITELIST.add(cleaned)

# Threat Scoring Thresholds
THREAT_THRESHOLD = float(os.getenv("THREAT_THRESHOLD", "10.0"))
SQLI_SCORE = 8.0
XSS_SCORE = 7.0
PATH_TRAVERSAL_SCORE = 9.0
BEHAVIORAL_ANOMALY_SCORE = 4.0
HIGH_ERROR_RATE_SCORE = 3.0

# Supervised ML Configuration
SUPERVISED_MODEL_NAME = os.getenv(
    "SUPERVISED_MODEL_NAME",
    "mrm8488/distilbert-uncased-finetuned-sql-injection"
)

# Unsupervised ML Configuration (IsolationForest)
ANOMALY_CONTAMINATION = 0.05
SLIDING_WINDOW_SECONDS = 60
MIN_SAMPLES_FOR_SCORING = 5
