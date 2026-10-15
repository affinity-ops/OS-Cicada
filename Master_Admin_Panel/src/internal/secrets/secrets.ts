// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

export interface SecretBackend {
  name(): string;
  getSecret(path: string): Promise<string>;
}

export class EnvBackend implements SecretBackend {
  name() {
    return 'env';
  }

  async getSecret(path: string): Promise<string> {
    const envKey = path.toUpperCase().replace(/\//g, '_');
    const val = process.env[envKey];
    if (val) {
      return val;
    }
    throw new Error(`Secret "${path}" not found in environment`);
  }
}

export class VaultBackend implements SecretBackend {
  private addr: string;
  private token: string;

  constructor() {
    const addr = process.env.CICADA_VAULT_ADDR;
    if (!addr) throw new Error('CICADA_VAULT_ADDR is required for vault backend');
    const token = process.env.CICADA_VAULT_TOKEN;
    if (!token) throw new Error('CICADA_VAULT_TOKEN is required for vault backend');

    this.addr = addr.replace(/\/$/, '');
    this.token = token;
  }

  name() {
    return 'vault';
  }

  async getSecret(path: string): Promise<string> {
    const response = await fetch(`${this.addr}/v1/secret/data/${path}`, {
      method: 'GET',
      headers: {
        'X-Vault-Token': this.token,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`Vault returned ${response.status}: ${await response.text()}`);
    }

    const json = await response.json();
    if (json.data && json.data.data && json.data.data.value) {
      return json.data.data.value;
    }
    throw new Error(`Secret "${path}" not found in vault response`);
  }
}

export class AWSBackend implements SecretBackend {
  private prefix: string;

  constructor() {
    const region = process.env.AWS_REGION || 'eu-west-1';
    this.prefix = process.env.CICADA_AWS_SECRET_PREFIX || 'cicada/';
    console.warn(`[SECRETS/AWS] Initialized AWS backend in region ${region}`);
  }

  name() {
    return 'aws';
  }

  async getSecret(path: string): Promise<string> {
    const fullPath = this.prefix + path;
    console.warn(`[SECRETS/AWS] getSecret: ${fullPath} — would call secretsmanager:GetSecretValue`);
    throw new Error('AWS Secrets Manager GetSecret not yet wired to SDK — use env backend for local dev');
  }
}

let activeBackend: SecretBackend | null = null;

export function getBackend(): SecretBackend {
  if (activeBackend) return activeBackend;

  const backendType = (process.env.CICADA_SECRET_BACKEND || 'env').toLowerCase();

  switch (backendType) {
    case 'env':
      activeBackend = new EnvBackend();
      break;
    case 'vault':
      activeBackend = new VaultBackend();
      break;
    case 'aws':
      activeBackend = new AWSBackend();
      break;
    default:
      throw new Error(`Unknown secret backend: "${backendType}" (supported: env, vault, aws)`);
  }

  return activeBackend;
}

export async function getSecret(path: string): Promise<string> {
  const backend = getBackend();
  return backend.getSecret(path);
}
