import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { createRequire } from 'node:module';
import { applySchema } from './schema.ts';

const require = createRequire(import.meta.url);

export function openDatabase(path: string): any {
	if (path !== ':memory:') {
		mkdirSync(dirname(path), { recursive: true });
	}
	
	let db: any;
	try {
		// Try Node >= 22.5.0 built-in SQLite first (zero dependencies/compilation)
		const { DatabaseSync } = require('node:sqlite');
		db = new DatabaseSync(path);
		// Polyfill pragma and transaction to match better-sqlite3 API
		db.pragma = (sql: string) => db.exec(`PRAGMA ${sql}`);
		db.transaction = (fn: any) => (...args: any[]) => {
			db.exec('BEGIN');
			try {
				const res = fn(...args);
				db.exec('COMMIT');
				return res;
			} catch (err) {
				db.exec('ROLLBACK');
				throw err;
			}
		};
	} catch (e) {
		// Fallback to better-sqlite3 (Node < 22.5.0)
		const Database = require('better-sqlite3');
		db = new Database(path);
	}

	db.pragma('journal_mode = WAL');
	db.pragma('foreign_keys = ON');
	applySchema(db);
	return db;
}
