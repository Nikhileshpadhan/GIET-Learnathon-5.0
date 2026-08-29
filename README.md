# Hostel Grievance Management System

A secure, high-performance web application designed for managing hostel grievances, enabling students to report issues and wardens to track and resolve them efficiently.

**🌟 What makes this project unique:** It features a custom-built, out-of-band **Machine Learning Security Agent** that silently monitors traffic in real-time, detecting and neutralizing zero-day attacks without slowing down the main web server.
## Project Overview

This project was built with modern web technologies, focusing on speed, reliability, and robust security. It provides distinct interfaces and permission levels for students and wardens, ensuring a streamlined process for facility maintenance and issue resolution.

### Technology Stack

*   **Frontend:** Svelte 5 (Runes mode) + SvelteKit 2
*   **Backend:** Hono v4 (running on Node.js/tsx)
*   **Database:** SQLite (via `better-sqlite3`)
*   **Security Layer:** Custom Python-based ML Security Daemon (Scikit-learn, Hugging Face Transformers)

## Security Architecture

Security is a foundational element of this application. Following a comprehensive security audit, the system has been hardened against common web vulnerabilities (OWASP Top 10) without compromising the user experience or business logic.

### Core Enhancements

*   **Strict Access Control:** Comprehensive mitigation of IDOR vulnerabilities. Students have guaranteed privacy for their grievances, while wardens maintain oversight.
*   **Data Protection:** Implementation of salted `scrypt` password hashing and secure, HttpOnly session management.
*   **Injection Defense:** Elimination of Stored XSS via safe reactive UI bindings and robust path traversal protections for file uploads.

For detailed security documentation, please refer to the `submission/` directory:
*   [`submission/SECURITY.md`](submission/SECURITY.md): Final security posture summary.
*   [`submission/THREAT-MODEL.md`](submission/THREAT-MODEL.md): System asset, threat actor, and boundary analysis.
*   [`submission/HARDENING.md`](submission/HARDENING.md): Matrix of identified vulnerabilities and their mitigations.

## ML-Powered Threat Detection

This project features a standalone, non-destructive Machine Learning Security Agent (`security_agent/`). Operating entirely out-of-band, it analyzes asynchronous telemetry emitted by the web server to detect and neutralize threats in real-time.

*   **Supervised Detection:** NLP models classify known attack payloads (SQLi, XSS, LFI).
*   **Unsupervised Detection:** Behavioral anomaly scoring identifies rapid scanning or fuzzing attempts.
*   **Automated Mitigation:** Infrastructure-level IP blocking (Nginx/UFW) with dry-run safety controls.

Learn more about the architecture and how to run live demonstrations in [`submission/security_agent.md`](submission/security_agent.md).

## Getting Started

### Prerequisites
*   Node.js (v18+)
*   Python 3.9+ (for the ML Security Agent)

### Installation

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd GIET-Learnathon-5.0-main
    ```

2.  **Install Web Application Dependencies:**
    ```bash
    npm install
    ```
    *(Note: If you see a warning like `npm warn allow-scripts 1 package has install scripts not yet covered by allowScripts`, you can safely ignore it. It is just a strict security setting in newer npm versions.)*

3.  **Install ML Agent Dependencies (Optional but recommended):**
    ```bash
    cd security_agent
    pip install -r requirements.txt
    cd ..
    ```

### Running the Application

**Start the Web Server:**
```bash
npm run dev:all
```
The application will be available at `http://localhost:3001`.

**Start the Security Daemon (in a separate terminal):**
```bash
cd security_agent
python -u daemon.py
```

### Testing

Run the automated test suites to verify functionality and security constraints:
```bash
npm test
npm run typecheck
```
