// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @cicada/sdk/user-context — User identity propagation.
 *
 * Enables "Agent X on behalf of User Y" audit trails by extracting
 * user identity from OAuth/OIDC tokens and encoding it into the
 * X-Cicada-User-Context header.
 *
 * The Gateway writes this context into the action ledger's
 * human_user_context column, making it queryable for audit and
 * compliance (SOC2/GDPR data subject access requests).
 */

/**
 * Represents a human user context for audit propagation.
 *
 * @example
 *   const ctx = UserContext.fromOAuthToken(jwtString);
 *   const headers = ctx.toHeaders();
 *   // { 'X-Cicada-User-Context': 'eyJ1c2VyX...' }
 */
class UserContext {
  /**
   * @param {Object} config
   * @param {string} config.userId - Unique user identifier (sub claim)
   * @param {string} [config.email=''] - User email
   * @param {string} [config.displayName=''] - Display name
   * @param {string} [config.idpIssuer=''] - Identity provider issuer
   * @param {string[]} [config.roles=[]] - User roles/groups
   * @param {string} [config.delegatedBy=''] - Delegator user (RFC 8693)
   * @param {Object} [config.metadata={}] - Additional claims
   */
  constructor({
    userId,
    email = '',
    displayName = '',
    idpIssuer = '',
    roles = [],
    delegatedBy = '',
    metadata = {},
  }) {
    this.userId = userId;
    this.email = email;
    this.displayName = displayName;
    this.idpIssuer = idpIssuer;
    this.roles = roles;
    this.delegatedBy = delegatedBy;
    this.metadata = metadata;
  }

  /**
   * Extract user context from a JWT access token.
   *
   * Decodes the JWT payload (no signature verification — that's the
   * Gateway's job) and maps standard OIDC claims to UserContext fields.
   *
   * @param {string} jwt - JWT string (header.payload.signature)
   * @param {Object} [options={}]
   * @param {boolean} [options.validate=false] - Throw on missing required claims
   * @returns {UserContext}
   */
  static fromOAuthToken(jwt, options = {}) {
    const { validate = false } = options;

    const parts = jwt.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format: expected 3 dot-separated parts');
    }

    let payload;
    try {
      const decoded = Buffer.from(parts[1], 'base64url').toString('utf8');
      payload = JSON.parse(decoded);
    } catch (err) {
      throw new Error(`Failed to decode JWT payload: ${err.message}`);
    }

    const userId = payload.sub || '';
    const idpIssuer = payload.iss || '';

    if (validate) {
      if (!userId) throw new Error('JWT missing required "sub" claim');
      if (!idpIssuer) throw new Error('JWT missing required "iss" claim');
    }

    // RFC 8693 delegation chain: the "act" claim indicates delegation
    const delegatedBy = payload.act?.sub || '';

    return new UserContext({
      userId,
      email: payload.email || '',
      displayName: payload.name || '',
      idpIssuer,
      roles: payload.roles || payload.groups || [],
      delegatedBy,
      metadata: payload.custom_claims || {},
    });
  }

  /**
   * Create a UserContext from a plain claims object.
   *
   * @param {Object} claims
   * @returns {UserContext}
   */
  static fromClaims(claims) {
    return new UserContext({
      userId: claims.user_id || claims.sub || claims.userId || '',
      email: claims.email || '',
      displayName: claims.display_name || claims.name || claims.displayName || '',
      idpIssuer: claims.idp_issuer || claims.iss || claims.idpIssuer || '',
      roles: claims.roles || claims.groups || [],
      delegatedBy: claims.delegated_by || claims.delegatedBy || '',
      metadata: claims.metadata || {},
    });
  }

  /**
   * Encode the context as a Base64 JSON string for the
   * X-Cicada-User-Context header.
   *
   * @returns {string} Base64url-encoded JSON
   */
  toHeaderValue() {
    const payload = {
      user_id: this.userId,
      idp_issuer: this.idpIssuer,
    };

    if (this.email) payload.email = this.email;
    if (this.displayName) payload.display_name = this.displayName;
    if (this.roles.length > 0) payload.roles = this.roles;
    if (this.delegatedBy) payload.delegated_by = this.delegatedBy;
    if (Object.keys(this.metadata).length > 0) payload.metadata = this.metadata;

    return Buffer.from(JSON.stringify(payload)).toString('base64url');
  }

  /**
   * Get HTTP headers dict for injection into requests.
   *
   * @returns {Object} Headers object with X-Cicada-User-Context
   */
  toHeaders() {
    return {
      'X-Cicada-User-Context': this.toHeaderValue(),
    };
  }

  /**
   * Validate the context has minimum required fields.
   *
   * @returns {string[]} List of validation issues (empty = valid)
   */
  validate() {
    const issues = [];
    if (!this.userId) issues.push('user_id is required');
    if (!this.idpIssuer) issues.push('idp_issuer is required');
    return issues;
  }
}

module.exports = { UserContext };
