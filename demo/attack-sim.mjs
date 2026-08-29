/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║   ML SECURITY SYSTEM — LIVE DEMO ATTACK SIMULATOR          ║
 * ║                                                             ║
 * ║   Run this in Terminal 2 while the ML Daemon runs in        ║
 * ║   Terminal 3. Watch real-time threat detections appear.      ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * USAGE:
 *   Terminal 1: npm run dev:all          (web app)
 *   Terminal 2: node demo/attack-sim.mjs (THIS SCRIPT)
 *   Terminal 3: cd security_agent && python daemon.py  (ML daemon)
 */

const BASE = 'http://localhost:3001';
const DELAY = 1500; // ms between attacks (slow enough to read in demo)

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function login(email, password) {
  const res = await fetch(`${BASE}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  const cookie = res.headers.getSetCookie?.()?.map(c => c.split(';')[0]).join('; ') || '';
  return cookie;
}

function header(text) {
  console.log('');
  console.log('-'.repeat(60));
  console.log(`  ${text}`);
  console.log('-'.repeat(60));
}

function step(emoji, label) {
  const time = new Date().toLocaleTimeString();
  console.log(`  ${emoji}  [${time}] ${label}`);
}

// ================================================================
// DEMO STARTS HERE
// ================================================================

console.log('');
console.log('==========================================================');
console.log('   ML SECURITY SYSTEM - LIVE ATTACK SIMULATION');
console.log('');
console.log('   Watch Terminal 3 (daemon.py) for real-time alerts!');
console.log('==========================================================');

// Get a valid session first
step('KEY', 'Logging in as student to get a valid session...');
const cookie = await login('student@example.test', 'student123');
step('OK', 'Session acquired. Starting attack simulation...');
await sleep(2000);

// ---------------------------------------------------------
// PHASE 1: Normal Traffic (should NOT trigger alerts)
// ---------------------------------------------------------
header('PHASE 1: Normal Legitimate Traffic (no alerts expected)');

step('USER', 'GET /api/me - Normal session check');
await fetch(`${BASE}/api/me`, { headers: { Cookie: cookie } });
await sleep(DELAY);

step('LIST', 'GET /api/grievances - Listing my grievances');
await fetch(`${BASE}/api/grievances`, { headers: { Cookie: cookie } });
await sleep(DELAY);

step('VIEW', 'GET /api/grievances/GRV-0001 - Viewing my own ticket');
await fetch(`${BASE}/api/grievances/GRV-0001`, { headers: { Cookie: cookie } });
await sleep(DELAY);

step('COMMENT', 'POST comment on GRV-0001 - Normal comment');
await fetch(`${BASE}/api/grievances/GRV-0001/comments`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Cookie: cookie },
  body: JSON.stringify({ body: 'The water leak is getting worse, please fix it soon.' })
});
await sleep(DELAY);

step('OK', 'Phase 1 complete - All normal traffic. Check daemon: should show NO threats.');
await sleep(3000);

// ---------------------------------------------------------
// PHASE 2: SQL Injection Attacks
// ---------------------------------------------------------
header("PHASE 2: SQL Injection Attacks");

step('SQLI', "SQLi #1: Classic ' OR '1'='1' in query parameter");
await fetch(`${BASE}/api/grievances?id=1' OR '1'='1' --`, { headers: { Cookie: cookie } });
await sleep(DELAY);

step('SQLI', "SQLi #2: UNION SELECT attack");
await fetch(`${BASE}/api/grievances?search=UNION ALL SELECT username, password_hash FROM users --`, {
  headers: { Cookie: cookie }
});
await sleep(DELAY);

step('SQLI', "SQLi #3: DROP TABLE in POST body");
await fetch(`${BASE}/api/grievances`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Cookie: cookie },
  body: JSON.stringify({
    title: "1'; DROP TABLE users; --",
    category: 'Room',
    description: "Robert'); DROP TABLE students; --"
  })
});
await sleep(DELAY);

step('SQLI', "SQLi #4: Blind SQLi with sleep");
await fetch(`${BASE}/api/grievances?id=1 AND SLEEP(5) --`, { headers: { Cookie: cookie } });
await sleep(DELAY);

step('CHECK', 'Check daemon output - should show SQLI detections with high confidence!');
await sleep(3000);

// ---------------------------------------------------------
// PHASE 3: XSS (Cross-Site Scripting) Attacks
// ---------------------------------------------------------
header('PHASE 3: XSS (Cross-Site Scripting) Attacks');

step('XSS', 'XSS #1: <script>alert("XSS")</script> in grievance title');
await fetch(`${BASE}/api/grievances`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Cookie: cookie },
  body: JSON.stringify({
    title: '<script>alert("XSS")</script>',
    category: 'Room',
    description: 'Testing XSS injection'
  })
});
await sleep(DELAY);

step('XSS', 'XSS #2: IMG onerror payload');
await fetch(`${BASE}/api/grievances`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Cookie: cookie },
  body: JSON.stringify({
    title: '"><img src=x onerror=alert(document.cookie)>',
    category: 'Other',
    description: 'Attempting stored XSS'
  })
});
await sleep(DELAY);

step('XSS', 'XSS #3: SVG/iframe injection');
await fetch(`${BASE}/api/grievances`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Cookie: cookie },
  body: JSON.stringify({
    title: '<svg onload=alert(1)><iframe src="javascript:alert(1)">',
    category: 'Other',
    description: '<embed src="data:text/html,<script>alert(1)</script>">'
  })
});
await sleep(DELAY);

step('CHECK', 'Check daemon output - should show XSS detections!');
await sleep(3000);

// ---------------------------------------------------------
// PHASE 4: Path Traversal / LFI Attacks
// ---------------------------------------------------------
header('PHASE 4: Path Traversal / LFI Attacks');

step('LFI', 'LFI #1: ../../etc/passwd in URL');
await fetch(`${BASE}/api/attachments/..%2f..%2f..%2f..%2fetc%2fpasswd`, {
  headers: { Cookie: cookie }
});
await sleep(DELAY);

step('LFI', 'LFI #2: Windows path traversal');
await fetch(`${BASE}/api/attachments/..%5c..%5c..%5cwindows%5cwin.ini`, {
  headers: { Cookie: cookie }
});
await sleep(DELAY);

step('LFI', 'LFI #3: Path traversal in POST body');
await fetch(`${BASE}/api/grievances`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Cookie: cookie },
  body: JSON.stringify({
    title: 'Normal looking title',
    category: 'Room',
    description: 'Check file at ../../../../etc/passwd and also /bin/bash'
  })
});
await sleep(DELAY);

step('CHECK', 'Check daemon output - should show PATH_TRAVERSAL detections!');
await sleep(3000);

// ---------------------------------------------------------
// PHASE 5: Rapid-Fire Scanning (Behavioral Anomaly)
// ---------------------------------------------------------
header('PHASE 5: Rapid-Fire Endpoint Scanning (Triggers Behavioral Anomaly)');

step('SCAN', 'Sending 50 rapid requests to diverse endpoints...');
const endpoints = [
  '/api/me', '/api/grievances', '/api/grievances/GRV-0001',
  '/api/grievances/GRV-0002', '/api/grievances/GRV-0003',
  '/api/admin', '/api/users', '/api/config', '/api/debug',
  '/api/internal', '/api/.env', '/api/backup', '/api/export',
  '/api/database', '/api/shell', '/api/phpinfo', '/api/wp-admin',
  '/api/login', '/api/register', '/api/reset-password',
];

for (let i = 0; i < 50; i++) {
  const ep = endpoints[i % endpoints.length];
  fetch(`${BASE}${ep}`, { headers: { Cookie: cookie } }).catch(() => {});
  if (i % 10 === 9) {
    step('SCAN', `  ...sent ${i + 1}/50 rapid requests`);
  }
}

await sleep(3000);
step('CHECK', 'Check daemon output - should show HIGH REQUEST RATE and ENDPOINT SCANNING anomalies!');
await sleep(2000);

// ---------------------------------------------------------
// PHASE 6: IDOR Attempts (Access Control Verification)
// ---------------------------------------------------------
header('PHASE 6: IDOR / Unauthorized Access Attempts');

step('IDOR', "IDOR #1: Trying to view another student's grievance (GRV-0003)");
const r1 = await fetch(`${BASE}/api/grievances/GRV-0003`, { headers: { Cookie: cookie } });
step(r1.status === 403 ? 'BLOCKED' : 'FAIL', `Response: ${r1.status} (expected 403 Forbidden)`);
await sleep(DELAY);

step('IDOR', "IDOR #2: Trying to modify another student's ticket");
const r2 = await fetch(`${BASE}/api/grievances/GRV-0003`, {
  method: 'PATCH',
  headers: { 'Content-Type': 'application/json', Cookie: cookie },
  body: JSON.stringify({ title: 'HACKED BY ATTACKER' })
});
step(r2.status === 403 ? 'BLOCKED' : 'FAIL', `Response: ${r2.status} (expected 403 Forbidden)`);
await sleep(DELAY);

step('IDOR', "IDOR #3: Student trying to escalate privilege (change status)");
const r3 = await fetch(`${BASE}/api/grievances/GRV-0001`, {
  method: 'PATCH',
  headers: { 'Content-Type': 'application/json', Cookie: cookie },
  body: JSON.stringify({ status: 'Resolved' })
});
step(r3.status === 403 ? 'BLOCKED' : 'FAIL', `Response: ${r3.status} (expected 403 Forbidden)`);
await sleep(DELAY);

// ================================================================
// DEMO COMPLETE
// ================================================================
console.log('');
console.log('==========================================================');
console.log('   DEMO COMPLETE');
console.log('');
console.log('   Check these files for evidence:');
console.log('   * logs/access.jsonl         (all request telemetry)');
console.log('   * logs/security_actions.log  (threat detections)');
console.log('   * logs/blocked_ips.txt       (IPs that would be blocked)');
console.log('');
console.log('   The daemon terminal shows real-time ML scoring!');
console.log('==========================================================');
console.log('');
