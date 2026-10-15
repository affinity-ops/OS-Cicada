// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Structured JSON logger for the Cicada Developer Portal.
 *
 * Outputs machine-parseable JSON to the server console with fields:
 *   { timestamp, level, service, message, ...context }
 *
 * Usage:
 *   import { logger } from '@/lib/logger';
 *   logger.info('Agent registered', { agent_id: 'ag-001', tenant_id: 't-001' });
 *   logger.error('Registration failed', { err: error.message });
 */

type LogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR';

interface LogEntry {
  timestamp: string;
  level: LogLevel;
  service: string;
  msg: string;
  [key: string]: unknown;
}

const SERVICE = 'cicada-developer-portal';
const LOG_FORMAT = process.env.LOG_FORMAT || 'json';

const LEVEL_ORDER: Record<LogLevel, number> = {
  DEBUG: 0,
  INFO: 1,
  WARN: 2,
  ERROR: 3,
};

const MIN_LEVEL: LogLevel = (
  (process.env.LOG_LEVEL?.toUpperCase() as LogLevel) || 'INFO'
);

function shouldLog(level: LogLevel): boolean {
  return (LEVEL_ORDER[level] ?? 1) >= (LEVEL_ORDER[MIN_LEVEL] ?? 1);
}

function emit(level: LogLevel, msg: string, context?: Record<string, unknown>) {
  if (!shouldLog(level)) return;

  const entry: LogEntry = {
    timestamp: new Date().toISOString(),
    level,
    service: SERVICE,
    msg,
    ...context,
  };

  if (LOG_FORMAT === 'text') {
    const ctx = context ? ' ' + JSON.stringify(context) : '';
    const method = level === 'ERROR' ? 'error' : level === 'WARN' ? 'warn' : 'log';
    console[method](`[${level}] ${msg}${ctx}`);
  } else {
    const method = level === 'ERROR' ? 'error' : level === 'WARN' ? 'warn' : 'log';
    console[method](JSON.stringify(entry));
  }
}

export const logger = {
  debug: (msg: string, ctx?: Record<string, unknown>) => emit('DEBUG', msg, ctx),
  info:  (msg: string, ctx?: Record<string, unknown>) => emit('INFO', msg, ctx),
  warn:  (msg: string, ctx?: Record<string, unknown>) => emit('WARN', msg, ctx),
  error: (msg: string, ctx?: Record<string, unknown>) => emit('ERROR', msg, ctx),

  child: (defaults: Record<string, unknown>) => ({
    debug: (msg: string, ctx?: Record<string, unknown>) => emit('DEBUG', msg, { ...defaults, ...ctx }),
    info:  (msg: string, ctx?: Record<string, unknown>) => emit('INFO', msg, { ...defaults, ...ctx }),
    warn:  (msg: string, ctx?: Record<string, unknown>) => emit('WARN', msg, { ...defaults, ...ctx }),
    error: (msg: string, ctx?: Record<string, unknown>) => emit('ERROR', msg, { ...defaults, ...ctx }),
  }),
};
