# ML-Powered Security Agent

## 1. What It Is

The ML-Powered Security Agent is a standalone, out-of-band monitoring and defense system for the Hostel Grievance Management application. 

Operating independently from the main Node.js web server, it acts as an invisible security wrapper. It analyzes application telemetry in real-time to detect, score, and automatically block malicious actors at the infrastructure level (e.g., via firewall or Nginx rules). Because it is completely decoupled, it is **100% non-destructive and fail-open**—if the security agent crashes, the web application continues to serve legitimate traffic with zero latency overhead.

## 2. ML Models Used

The agent leverages a dual-layered approach combining both Supervised and Unsupervised Machine Learning techniques:

*   **Supervised NLP Model (Payload Classification):**
    *   **Model:** Hugging Face Transformers (`mrm8488/distilbert-uncased-finetuned-sql-injection`).
    *   **Purpose:** Classifies specific, known attack payloads embedded within HTTP requests (such as SQL Injection, Cross-Site Scripting (XSS), and Path Traversal). 
    *   **Optimization:** Configured for CPU-only inference for low-power compatibility, backed by a high-speed heuristic regex engine that provides instant pre-filtering before passing payloads to the neural network.

*   **Unsupervised Behavioral Model (Anomaly Detection):**
    *   **Model:** Scikit-Learn's `IsolationForest`.
    *   **Purpose:** Detects novel, unknown attacks ("zero-days") and behavioral anomalies without requiring labeled training data.
    *   **Features Tracked:** It monitors a sliding time window of IP behavior, calculating features like request frequency, error rate percentage, endpoint diversity (fuzzing/scanning), and average payload size.

## 3. How It Works

1.  **Telemetry Emission:** When a client interacts with the web app, a lightweight, non-blocking middleware (`security-logger.ts`) extracts request metadata (IP, path, query, status, bounded payload snippet). It uses a fire-and-forget mechanism to append this data as a JSON line to `logs/access.jsonl`.
2.  **Continuous Monitoring:** The Python daemon (`daemon.py`) asynchronously tails `logs/access.jsonl` in real-time, functioning much like a high-speed log reader.
3.  **Threat Evaluation:**
    *   The event text is evaluated by the **Supervised Detector** for embedded attack vectors.
    *   The event context is added to the IP's behavioral history and scored by the **Unsupervised Detector** for anomalous patterns.
4.  **Scoring & Mitigation:** If an attack or anomaly is detected, the IP accumulates a threat score. If the score exceeds the configurable `THREAT_THRESHOLD`, the `blocker.py` module automatically implements an infrastructure-level block (e.g., adding a drop rule in `iptables`, `ufw`, Windows Firewall, or Nginx's deny list).

## 4. How to Test It (Live Demonstration)

You can demonstrate the ML system's real-time detection and blocking capabilities using the provided attack simulation script. This requires running three separate terminal windows simultaneously.

### Step 1: Start the Web Application
In **Terminal 1**, start the standard application:
```bash
npm run dev:all
```

### Step 2: Start the ML Security Daemon
In **Terminal 2**, start the security daemon. (The `-u` flag disables Python output buffering so you can watch detections print to the screen instantly).
```bash
cd security_agent
python -u daemon.py
```

### Step 3: Run the Attack Simulator
In **Terminal 3**, execute the live demo script. This script systematically escalates from normal traffic to aggressive attacks.
```bash
node demo/attack-sim.mjs
```

### Observing the Results

As the simulator runs in Terminal 3, watch Terminal 2. You will observe the ML daemon correctly ignoring Phase 1 (Normal Traffic), and subsequently firing real-time alerts for:
*   **SQLI** (Supervised NLP detection)
*   **XSS** (Supervised NLP detection)
*   **PATH_TRAVERSAL** (Supervised NLP detection)
*   **High request rate & Endpoint scanning** (Unsupervised Behavioral anomaly)

Following the simulation, you can verify the automated responses by inspecting `logs/blocked_ips.txt` to see which simulated attacking IPs reached the threat threshold and were blocked.
