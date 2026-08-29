# Security Hardening Report

This document records the specific security vulnerabilities identified during the audit and the non-destructive remediation strategies implemented to secure the Hostel Grievance Management System.

## Hardening Matrix

| Finding | Risk Level | Change Implemented | Verification Strategy | Residual Risk |
| :--- | :--- | :--- | :--- | :--- |
| **Insecure Direct Object Reference (IDOR) on Grievances** | Critical | Implemented `assertCanViewGrievance(user, row)` in all `GET` and `PATCH` endpoints. Validates ownership before returning data. | E2E Integration tests confirm `403 Forbidden` when attempting to access peers' tickets. | Low |
| **Unauthorized Modification (Privilege Escalation)** | High | Hardened `PATCH /api/grievances/:id` to explicitly reject `status` updates if the user's role is not `warden`. | Automated tests verify students receive `403` when modifying the `status` field. | Low |
| **Stored Cross-Site Scripting (XSS)** | High | Modified `src/lib/components/app/comment-timeline.svelte` to replace `{@html comment.body}` with safe reactive text binding `{comment.body}`. | Attempted XSS payloads render as plain text in the UI instead of executing. | Low |
| **Path Traversal & Arbitrary File Uploads** | Critical | Updated `src/server/storage/attachments.ts` to disregard user-provided filenames. Files are now saved using `randomBytes(16).toString('hex') + extension`. | File uploads succeed, but traversal payloads (`../`) are safely hashed into harmless filenames. | Low |
| **Insecure Session Management** | High | Added database token deletion on `/api/logout`. Enforced expiration checks (`s.expires_at > nowIso()`). Added `HttpOnly`, `SameSite=Lax`, and `Secure` to cookies. | Verified `401 Unauthorized` after logout; verified cookie attributes in browser dev tools. | Low (Session hijacking risk remains if client machine is compromised). |
| **Weak Password Storage** | Critical | Upgraded from plain/weak hashing to salted `scrypt` key derivation. Maintained backward compatibility for legacy hashes. | Login functions correctly; database inspection shows secure `scrypt` hashes for new/updated passwords. | Low |
| **Missing Security Headers** | Medium | Injected `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Referrer-Policy` headers into server responses. | `curl -I` and E2E tests confirm headers are present on API responses. | Low |
| **Information Disclosure on 500 Errors** | Medium | Sanitized unhandled 500 error outputs in `src/server/http/errors.ts` to return a generic `'Internal server error.'` message. | Triggering a forced error returns no stack traces or database schema details. | Low |
