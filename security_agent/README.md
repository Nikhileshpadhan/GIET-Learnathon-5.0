# ML-Powered Log Monitoring & Automated IP-Blocking Agent

A lightweight, asynchronous, decoupled security sidecar for the **HostelGrievance** portal.

---

## Features

1. **Zero Latency Impact:** Hono web server logs telemetry asynchronously without blocking client responses.
2. **Supervised Attack Detection:** Classifies SQLi, XSS, Path Traversal, and Command Injections using Hugging Face Transformers and CPU-optimized pattern heuristics.
3. **Unsupervised Anomaly Detection:** Out-of-the-box `IsolationForest` (Scikit-Learn) scores behavioral anomalies (burst rates, scanning, error rate spikes).
4. **Automated Infrastructure IP Blocking:**
   - Linux `ufw` / `iptables`
   - Windows `netsh advfirewall`
   - Nginx `nginx_blockips.conf` (`include nginx_blockips.conf;` in `nginx.conf`)
5. **Safety Controls:**
   - **Dry-Run Mode (`DRY_RUN = True`):** Logs intended blocks to `logs/blocked_ips.txt` and `logs/security_actions.log` without altering firewall rules.
   - **IP Whitelisting:** Immune safe list (`127.0.0.1`, `::1`, `localhost`, etc.).
   - **100% Fail-Open:** Website continues running seamlessly even if the Python daemon is stopped or crashes.

---

## Quickstart

### 1. Install Python Dependencies
```sh
cd security_agent
pip install -r requirements.txt
```
*(On ultra-low-power devices, simply installing `scikit-learn` and `numpy` is sufficient; the agent gracefully activates CPU heuristics if `torch`/`transformers` are not installed).*

### 2. Run the Security Daemon
```sh
# Run in Dry-Run mode (Default)
python daemon.py

# Or run in Live Enforcement mode
SECURITY_DRY_RUN=false python daemon.py
```

---

## Log Output Files

All logs are stored in the project `logs/` directory:
- `logs/access.jsonl`: Real-time streaming HTTP telemetry.
- `logs/security_actions.log`: Audit trail of detected threats and blocking actions.
- `logs/blocked_ips.txt`: List of all blocked IPs with timestamps and reasons.
- `logs/nginx_blockips.conf`: Nginx deny configuration block.
