import { Hono } from 'hono';
import type { Database } from 'better-sqlite3';
import type { AppEnv } from './env.ts';
import { handleError, HttpError } from './http/errors.ts';
import { authRoutes } from './routes/auth.ts';
import { grievanceRoutes } from './routes/grievances.ts';
import { attachmentRoutes } from './routes/attachments.ts';
import { securityLogger } from './middleware/security-logger.ts';
import { cors } from 'hono/cors';

export type CreateAppOptions = {
	db: Database;
	uploadsDir: string;
};

const ALLOWED_ORIGINS = new Set([
	'http://localhost:5173',
	'http://127.0.0.1:5173',
	'http://localhost:4173',
	'http://127.0.0.1:4173',
	'http://localhost:3001',
	'http://127.0.0.1:3001'
]);

export function createApp(options: CreateAppOptions) {
	const app = new Hono<AppEnv>();

	app.use('*', securityLogger());

	app.use('*', async (c, next) => {
		c.header('X-Content-Type-Options', 'nosniff');
		c.header('X-Frame-Options', 'DENY');
		c.header('Referrer-Policy', 'strict-origin-when-cross-origin');
		c.set('db', options.db);
		c.set('uploadsDir', options.uploadsDir);
		await next();
	});

	app.use(
		'/api/*',
		cors({
			origin: (origin) => {
				if (!origin) return null;
				if (ALLOWED_ORIGINS.has(origin)) return origin;
				return null;
			},
			credentials: true,
			allowMethods: ['GET', 'POST', 'PATCH', 'OPTIONS'],
			allowHeaders: ['Content-Type', 'Cookie']
		})
	);

	app.onError((err, c) => handleError(err, c));

	app.notFound((c) => c.json({ error: 'Not found.', code: 'not_found' }, 404));

	app.get('/api/health', (c) => c.json({ ok: true }));
	app.route('/api', authRoutes);
	app.route('/api/grievances', grievanceRoutes);
	app.route('/api/attachments', attachmentRoutes);

	app.all('/api/*', () => {
		throw new HttpError(404, 'not_found', 'Not found.');
	});

	return app;
}
