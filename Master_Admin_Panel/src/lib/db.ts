// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';

const DATA_DIR = path.join(process.cwd(), 'data');
const DB_PATH = path.join(DATA_DIR, 'admin.db');

let _db: Database.Database | null = null;

/** Get the singleton database connection, creating it on first call. */
export function getDb(): Database.Database {
  if (_db) return _db;

  // Ensure data directory exists
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  _db = new Database(DB_PATH);

  // Enable WAL mode for better concurrent read performance
  _db.pragma('journal_mode = WAL');
  _db.pragma('foreign_keys = ON');

  return _db;
}

/** Initialize the database schema. Safe to call multiple times (IF NOT EXISTS). */
export function initSchema(): void {
  const db = getDb();

  // Create tables. The .pairing_mode flag file is managed outside the DB
  // (it's a gating mechanism, not persistent state), so it stays as a file.
  db.exec(`
    CREATE TABLE IF NOT EXISTS challenges (
      session_id TEXT PRIMARY KEY NOT NULL,
      challenge_id TEXT NOT NULL,
      browser_ip TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS devices (
      id TEXT PRIMARY KEY NOT NULL,
      name TEXT NOT NULL DEFAULT '',
      type TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'active',
      paired_at TEXT NOT NULL DEFAULT (datetime('now')),
      last_used TEXT NOT NULL DEFAULT (datetime('now')),
      ed25519_pub TEXT NOT NULL DEFAULT '',
      mldsa_pub TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS heartbeats (
      gateway_id TEXT PRIMARY KEY NOT NULL,
      version TEXT NOT NULL DEFAULT '',
      uptime_seconds INTEGER NOT NULL DEFAULT 0,
      agents_registered INTEGER NOT NULL DEFAULT 0,
      postgres_healthy INTEGER NOT NULL DEFAULT 1,
      last_seen TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
}

/** Migrate existing data from JSON files into SQLite. Idempotent. */
export function migrateFromJson(): void {
  const db = getDb();

  // Migrate challenges
  const challengesPath = path.join(DATA_DIR, 'challenges.json');
  if (fs.existsSync(challengesPath)) {
    const rowCount = db.prepare('SELECT COUNT(*) as c FROM challenges').get() as { c: number };
    if (rowCount.c === 0) {
      const data = JSON.parse(fs.readFileSync(challengesPath, 'utf-8') || '[]');
      const insert = db.prepare(
        'INSERT OR IGNORE INTO challenges (session_id, challenge_id, browser_ip, status, created_at) VALUES (?, ?, ?, ?, ?)'
      );
      const tx = db.transaction((items: Record<string, unknown>[]) => {
        for (const item of items) {
          insert.run(item.session_id, item.challenge_id, item.browser_ip || '', item.status, item.created_at);
        }
      });
      tx(data);
      console.log(`Migrated ${data.length} challenges from JSON`);
    }
  }

  // Migrate devices
  const devicesPath = path.join(DATA_DIR, 'devices.json');
  if (fs.existsSync(devicesPath)) {
    const rowCount = db.prepare('SELECT COUNT(*) as c FROM devices').get() as { c: number };
    if (rowCount.c === 0) {
      const data = JSON.parse(fs.readFileSync(devicesPath, 'utf-8') || '[]');
      const insert = db.prepare(
        'INSERT OR IGNORE INTO devices (id, name, type, status, paired_at, last_used, ed25519_pub, mldsa_pub) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
      );
      const tx = db.transaction((items: Record<string, unknown>[]) => {
        for (const item of items) {
          const keys = (item.keys as Record<string, string>) || {};
          insert.run(
            item.id || '',
            item.name || '',
            item.type || '',
            item.status || 'active',
            item.paired_at || new Date().toISOString(),
            item.last_used || new Date().toISOString(),
            keys.ed25519 || '',
            keys.mldsa || '',
          );
        }
      });
      tx(data);
      console.log(`Migrated ${data.length} devices from JSON`);
    }
  }

  // Migrate heartbeats
  const heartbeatsPath = path.join(DATA_DIR, 'heartbeats.json');
  if (fs.existsSync(heartbeatsPath)) {
    const rowCount = db.prepare('SELECT COUNT(*) as c FROM heartbeats').get() as { c: number };
    if (rowCount.c === 0) {
      const data = JSON.parse(fs.readFileSync(heartbeatsPath, 'utf-8') || '[]');
      const insert = db.prepare(
        'INSERT OR IGNORE INTO heartbeats (gateway_id, version, uptime_seconds, agents_registered, postgres_healthy, last_seen) VALUES (?, ?, ?, ?, ?, ?)'
      );
      const tx = db.transaction((items: Record<string, unknown>[]) => {
        for (const item of items) {
          insert.run(
            item.gateway_id || item.id || '',
            item.version || '',
            item.uptime_seconds || 0,
            item.agents_registered || 0,
            item.postgres_healthy ? 1 : 0,
            item.last_seen || new Date().toISOString(),
          );
        }
      });
      tx(data);
      console.log(`Migrated ${data.length} heartbeats from JSON`);
    }
  }
}
