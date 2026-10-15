// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Tests for @cicada/sdk/user-context — User identity propagation.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { UserContext } = require('./user-context');


// ── Construction ─────────────────────────────────────────────────

describe('UserContext construction', () => {
  it('sets all fields from constructor', () => {
    const ctx = new UserContext({
      userId: 'u-123',
      email: 'alice@corp.io',
      displayName: 'Alice',
      idpIssuer: 'https://accounts.google.com',
      roles: ['admin', 'viewer'],
      delegatedBy: 'u-999',
      metadata: { team: 'platform' },
    });

    assert.equal(ctx.userId, 'u-123');
    assert.equal(ctx.email, 'alice@corp.io');
    assert.equal(ctx.idpIssuer, 'https://accounts.google.com');
    assert.deepEqual(ctx.roles, ['admin', 'viewer']);
    assert.equal(ctx.delegatedBy, 'u-999');
  });

  it('defaults empty strings and arrays', () => {
    const ctx = new UserContext({ userId: 'x' });
    assert.equal(ctx.email, '');
    assert.equal(ctx.displayName, '');
    assert.deepEqual(ctx.roles, []);
    assert.deepEqual(ctx.metadata, {});
  });
});


// ── fromOAuthToken ───────────────────────────────────────────────

describe('UserContext.fromOAuthToken', () => {
  function makeJWT(payload) {
    const header = Buffer.from('{}').toString('base64url');
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    return `${header}.${body}.sig`;
  }

  it('extracts standard claims', () => {
    const jwt = makeJWT({
      sub: 'u-42',
      email: 'bob@corp.io',
      name: 'Bob',
      iss: 'https://auth0.com',
      roles: ['operator'],
    });

    const ctx = UserContext.fromOAuthToken(jwt);
    assert.equal(ctx.userId, 'u-42');
    assert.equal(ctx.email, 'bob@corp.io');
    assert.equal(ctx.displayName, 'Bob');
    assert.equal(ctx.idpIssuer, 'https://auth0.com');
    assert.deepEqual(ctx.roles, ['operator']);
  });

  it('uses groups claim as fallback', () => {
    const jwt = makeJWT({ sub: 'u-1', iss: 'x', groups: ['eng'] });
    const ctx = UserContext.fromOAuthToken(jwt);
    assert.deepEqual(ctx.roles, ['eng']);
  });

  it('extracts RFC 8693 delegation chain', () => {
    const jwt = makeJWT({
      sub: 'agent-x',
      iss: 'https://auth.corp.io',
      act: { sub: 'u-human' },
    });
    const ctx = UserContext.fromOAuthToken(jwt);
    assert.equal(ctx.delegatedBy, 'u-human');
  });

  it('throws on invalid JWT format', () => {
    assert.throws(
      () => UserContext.fromOAuthToken('not-a-jwt'),
      /Invalid JWT format/,
    );
  });

  it('throws on malformed payload', () => {
    assert.throws(
      () => UserContext.fromOAuthToken('a.!!!invalid!!!.b'),
      /Failed to decode/,
    );
  });

  it('throws on missing sub when validate=true', () => {
    const jwt = makeJWT({ iss: 'x' });
    assert.throws(
      () => UserContext.fromOAuthToken(jwt, { validate: true }),
      /missing required "sub"/,
    );
  });

  it('throws on missing iss when validate=true', () => {
    const jwt = makeJWT({ sub: 'x' });
    assert.throws(
      () => UserContext.fromOAuthToken(jwt, { validate: true }),
      /missing required "iss"/,
    );
  });

  it('does not throw on missing claims when validate=false', () => {
    const jwt = makeJWT({});
    const ctx = UserContext.fromOAuthToken(jwt);
    assert.equal(ctx.userId, '');
    assert.equal(ctx.idpIssuer, '');
  });
});


// ── fromClaims ───────────────────────────────────────────────────

describe('UserContext.fromClaims', () => {
  it('maps standard field names', () => {
    const ctx = UserContext.fromClaims({
      user_id: 'u-1',
      email: 'a@b.com',
      display_name: 'A',
      idp_issuer: 'https://x',
      roles: ['r1'],
    });
    assert.equal(ctx.userId, 'u-1');
    assert.equal(ctx.displayName, 'A');
  });

  it('maps alternate field names', () => {
    const ctx = UserContext.fromClaims({
      sub: 'u-2',
      name: 'B',
      iss: 'https://y',
      groups: ['g1'],
    });
    assert.equal(ctx.userId, 'u-2');
    assert.equal(ctx.displayName, 'B');
    assert.deepEqual(ctx.roles, ['g1']);
  });
});


// ── Header Serialization ─────────────────────────────────────────

describe('Header serialization', () => {
  it('toHeaderValue roundtrips correctly', () => {
    const ctx = new UserContext({
      userId: 'u-rt',
      email: 'rt@test.com',
      idpIssuer: 'https://auth.test',
      roles: ['admin'],
    });

    const encoded = ctx.toHeaderValue();
    const decoded = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));

    assert.equal(decoded.user_id, 'u-rt');
    assert.equal(decoded.email, 'rt@test.com');
    assert.equal(decoded.idp_issuer, 'https://auth.test');
    assert.deepEqual(decoded.roles, ['admin']);
  });

  it('toHeaders returns correct header key', () => {
    const ctx = new UserContext({ userId: 'u-1', idpIssuer: 'x' });
    const headers = ctx.toHeaders();
    assert.ok('X-Cicada-User-Context' in headers);
  });

  it('omits empty roles from payload', () => {
    const ctx = new UserContext({ userId: 'u-1', idpIssuer: 'x' });
    const encoded = ctx.toHeaderValue();
    const decoded = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    assert.ok(!('roles' in decoded));
  });
});


// ── Validation ───────────────────────────────────────────────────

describe('UserContext.validate', () => {
  it('valid context returns empty issues', () => {
    const ctx = new UserContext({ userId: 'u-1', idpIssuer: 'https://x' });
    assert.deepEqual(ctx.validate(), []);
  });

  it('missing userId flagged', () => {
    const ctx = new UserContext({ userId: '', idpIssuer: 'https://x' });
    assert.ok(ctx.validate().some(i => i.includes('user_id')));
  });

  it('missing idpIssuer flagged', () => {
    const ctx = new UserContext({ userId: 'u-1' });
    assert.ok(ctx.validate().some(i => i.includes('idp_issuer')));
  });
});
