// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Tests for the structured JSON logger utility.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// We need to import dynamically so we can manipulate env vars before import.
describe('logger', () => {
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    originalEnv = { ...process.env };
    vi.restoreAllMocks();
  });

  afterEach(() => {
    process.env = originalEnv;
    vi.resetModules();
  });

  async function getLogger() {
    // Force re-import to pick up env changes.
    const mod = await import('@/lib/logger');
    return mod.logger;
  }

  it('emits JSON with required fields', async () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const logger = await getLogger();

    logger.info('test message', { agent_id: 'ag-001' });

    expect(spy).toHaveBeenCalledOnce();
    const output = JSON.parse(spy.mock.calls[0][0] as string);
    expect(output.level).toBe('INFO');
    expect(output.service).toBe('cicada-dashboard');
    expect(output.msg).toBe('test message');
    expect(output.agent_id).toBe('ag-001');
    expect(output.timestamp).toBeDefined();
    spy.mockRestore();
  });

  it('logs errors to console.error', async () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const logger = await getLogger();

    logger.error('pipeline failed', { err: 'timeout' });

    expect(spy).toHaveBeenCalledOnce();
    const output = JSON.parse(spy.mock.calls[0][0] as string);
    expect(output.level).toBe('ERROR');
    expect(output.err).toBe('timeout');
    spy.mockRestore();
  });

  it('logs warnings to console.warn', async () => {
    const spy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const logger = await getLogger();

    logger.warn('rate limit approaching');

    expect(spy).toHaveBeenCalledOnce();
    const output = JSON.parse(spy.mock.calls[0][0] as string);
    expect(output.level).toBe('WARN');
    spy.mockRestore();
  });

  it('child logger includes default fields', async () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const logger = await getLogger();

    const child = logger.child({ trace_id: 'tr-123', agent_id: 'ag-billing' });
    child.info('session issued');

    const output = JSON.parse(spy.mock.calls[0][0] as string);
    expect(output.trace_id).toBe('tr-123');
    expect(output.agent_id).toBe('ag-billing');
    expect(output.msg).toBe('session issued');
    spy.mockRestore();
  });

  it('child logger allows context override', async () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const logger = await getLogger();

    const child = logger.child({ trace_id: 'tr-base' });
    child.info('msg', { trace_id: 'tr-override' });

    const output = JSON.parse(spy.mock.calls[0][0] as string);
    expect(output.trace_id).toBe('tr-override');
    spy.mockRestore();
  });
});
