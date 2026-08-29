import { appendFile, mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { MiddlewareHandler } from 'hono';
import { REPO_ROOT } from '../config.ts';

const LOG_DIR = join(REPO_ROOT, 'logs');
const ACCESS_LOG_FILE = join(LOG_DIR, 'access.jsonl');

let dirEnsured = false;

async function ensureLogDir() {
	if (!dirEnsured) {
		try {
			await mkdir(LOG_DIR, { recursive: true });
			dirEnsured = true;
		} catch {
			/* fail-open */
		}
	}
}

/**
 * Non-blocking, completely fail-open request logging middleware for ML security analysis.
 * Captures metadata (IP, path, method, headers, query, status, duration) asynchronously
 * without holding or blocking the client response cycle.
 */
export function securityLogger(): MiddlewareHandler {
	return async (c, next) => {
		const start = Date.now();
		const clientIp =
			c.req.header('x-forwarded-for')?.split(',')[0].trim() ||
			c.req.header('x-real-ip') ||
			'127.0.0.1';

		const method = c.req.method;
		const path = c.req.path;
		const query = c.req.query();
		const userAgent = c.req.header('user-agent') ?? '';

		// Capture request payload safely if text/json (cloned so body is not consumed)
		let payloadSample = '';
		const contentType = c.req.header('content-type') ?? '';
		if (
			(method === 'POST' || method === 'PATCH' || method === 'PUT') &&
			(contentType.includes('application/json') || contentType.includes('application/x-www-form-urlencoded'))
		) {
			try {
				const cloned = c.req.raw.clone();
				const text = await cloned.text();
				payloadSample = text.slice(0, 2048); // Bound sample size for high performance
			} catch {
				/* fail-open */
			}
		}

		// Proceed with the request immediately
		await next();

		const durationMs = Date.now() - start;
		const status = c.res.status;

		const logEntry = {
			timestamp: new Date().toISOString(),
			ip: clientIp,
			method,
			path,
			query,
			status,
			duration_ms: durationMs,
			user_agent: userAgent,
			payload: payloadSample
		};

		// Fire-and-forget asynchronous write — zero impact on client response
		setImmediate(async () => {
			try {
				await ensureLogDir();
				await appendFile(ACCESS_LOG_FILE, JSON.stringify(logEntry) + '\n', 'utf8');
			} catch {
				// Fail-open: Logging error must never affect application execution
			}
		});
	};
}
