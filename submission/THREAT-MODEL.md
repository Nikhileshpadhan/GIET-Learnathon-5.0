# Threat Model: Hostel Grievance Management System

This document outlines the threat landscape for the Hostel Grievance Management System, detailing critical assets, potential adversaries, trust boundaries, and primary attack vectors.

## 1. System Assets

The application manages several critical assets that require protection against unauthorized access, modification, or destruction:

| Asset Category | Description | Criticality |
| :--- | :--- | :--- |
| **User Data** | Student identifying details, contact information, and room assignments. | High |
| **Grievance Records** | Descriptions of issues, comments, timestamps, and current resolution status. | Medium |
| **Media Attachments** | Photos and documents uploaded as evidence for grievances. | Medium |
| **Credentials & Sessions** | Password hashes, active session tokens, and authentication cookies. | Critical |
| **System Infrastructure** | Application source code, SQLite database file (`data/hostel.db`), and uploaded files directory. | Critical |

## 2. Threat Actors

We have identified three primary categories of adversaries with varying motivations and capabilities:

*   **Unauthenticated External Attacker:** An external entity attempting to exploit network-facing vulnerabilities (e.g., brute-force login, unauthenticated API access, directory traversal) without legitimate credentials.
*   **Malicious/Curious Student (Authenticated):** A legitimate user attempting horizontal privilege escalation (accessing peers' grievances) or vertical privilege escalation (performing warden-only actions like changing grievance status).
*   **Compromised Client / Automated Script:** Malware or automated attacks executing XSS payloads or CSRF attempts to hijack active sessions or manipulate data on behalf of an authenticated victim.

## 3. Trust Boundaries

The system architecture defines clear boundaries where data transitions between trusted and untrusted environments:

*   **Internet ↔ Reverse Proxy / Web Server:** The primary boundary. All incoming HTTP/HTTPS traffic is inherently untrusted.
*   **Web Server ↔ Node.js Application:** Traffic is semi-trusted but payload content (headers, body, query parameters) must be validated and sanitized.
*   **Application ↔ Database (SQLite):** The application trusts the database, but input must be parameterized to prevent SQL injection.
*   **Application ↔ Filesystem:** Uploaded files are untrusted; their names and contents must be sanitized before writing to the disk.

## 4. Attack Surface & Key Attack Paths

Based on the architecture and boundaries, the following attack vectors represent the highest risk:

| Attack Vector | Description | Primary Mitigation |
| :--- | :--- | :--- |
| **Broken Access Control (IDOR)** | Attackers manipulating IDs in URLs/APIs (e.g., `/api/grievances/GRV-0002`) to access unauthorized records. | Enforce strict ownership validation (`assertCanViewGrievance`) on every restricted endpoint. |
| **Injection (XSS/SQLi)** | Injecting malicious scripts into grievance titles/comments (Stored XSS) or manipulating database queries. | Use reactive UI frameworks (Svelte) safely; use parameterized queries in `better-sqlite3`. |
| **Path Traversal & Arbitrary Uploads** | Uploading malicious files (e.g., `.php`, `.exe`) or manipulating filenames to overwrite system files (`../../etc/passwd`). | Enforce strict file extension whitelists and generate random, server-controlled filenames for all uploads. |
| **Session Hijacking & Fixation** | Stealing session tokens via XSS or network sniffing. | Implement `HttpOnly`, `Secure`, and `SameSite` cookie attributes; expire sessions appropriately. |
| **Privilege Escalation** | Students exploiting endpoints to modify fields they shouldn't (e.g., changing grievance `status`). | Implement field-level authorization checks in `PATCH` endpoints. |
