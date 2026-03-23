/**
 * AES-256-GCM encryption for sensitive fields in JSONB columns.
 *
 * Framework-agnostic field encryption. Supports graceful passthrough when no
 * encryption key is configured.
 *
 * Environment:
 *   ENCRYPTION_MASTER_KEY — 32-byte hex string (64 hex chars)
 */

import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96-bit nonce recommended for GCM

interface EncryptResult {
  ciphertext: string;
  iv: string;
  tag: string;
  passthrough?: boolean;
}

interface EncryptedEnvelope {
  __enc: true;
  c: string;
  iv: string;
  t: string;
}

interface EncryptionConfig {
  masterKey?: string | null;
  enabled?: boolean;
  algorithm?: string;
}

let _keyWarned = false;
let _config: EncryptionConfig = {};

/**
 * Validate encryption configuration on startup.
 * In production, warn loudly if key is missing.
 */
export function validateEncryptionConfig(
  config?: EncryptionConfig,
): void {
  if (config) {
    _config = config;
  }

  const key = getMasterKey();
  if (!key && process.env.NODE_ENV === 'production') {
    console.error(
      '[encryption] ⚠️  ENCRYPTION_MASTER_KEY not set in production — ' +
      'sensitive data will be stored UNENCRYPTED. Set a 32-byte hex key (64 chars).',
    );
  }
}

function getMasterKey(): Buffer | null {
  // Check explicit config first
  if (_config.masterKey !== undefined) {
    if (!_config.masterKey) return null;
    if (_config.masterKey.length !== 64) return null;
    return Buffer.from(_config.masterKey, 'hex');
  }

  // Fall back to environment variable
  const hex = process.env.ENCRYPTION_MASTER_KEY;
  if (!hex || hex.length !== 64) {
    return null;
  }

  return Buffer.from(hex, 'hex');
}

/**
 * Returns true if encryption is configured.
 */
export function isEncryptionEnabled(): boolean {
  return getMasterKey() !== null;
}

function warnOnce(): void {
  if (!_keyWarned && !isEncryptionEnabled()) {
    console.warn(
      '[encryption] ENCRYPTION_MASTER_KEY not set — ' +
      'sensitive data stored unencrypted',
    );
    _keyWarned = true;
  }
}

/**
 * Encrypt a plaintext value.
 */
export function encrypt(
  plaintext: string | number,
): EncryptResult {
  const key = getMasterKey();
  if (!key) {
    warnOnce();
    return {
      ciphertext: String(plaintext),
      iv: '',
      tag: '',
      passthrough: true,
    };
  }

  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv);

  const text = String(plaintext);
  let encrypted = cipher.update(text, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  const tag = cipher.getAuthTag();

  return {
    ciphertext: encrypted,
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
  };
}

/**
 * Decrypt a ciphertext.
 */
export function decrypt(
  ciphertext: string,
  iv: string,
  tag: string,
): string {
  const key = getMasterKey();
  if (!key) {
    warnOnce();
    return ciphertext;
  }

  const decipher = createDecipheriv(
    ALGORITHM,
    key,
    Buffer.from(iv, 'base64'),
  );
  decipher.setAuthTag(Buffer.from(tag, 'base64'));

  let decrypted = decipher.update(ciphertext, 'base64', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

/**
 * Encrypt a field value and return a JSON string for Prisma JSONB storage.
 * Stores as: { __enc: true, c: ciphertext, iv: iv, t: tag }
 *
 * If no encryption key is configured, stores the plaintext value.
 */
export function encryptField(
  value: string | number | null | undefined,
): string | null {
  if (value == null) {
    return null;
  }

  const result = encrypt(value);

  if (result.passthrough) {
    return String(value);
  }

  return JSON.stringify({
    __enc: true,
    c: result.ciphertext,
    iv: result.iv,
    t: result.tag,
  });
}

/**
 * Decrypt a field from JSONB storage.
 * Returns the original value (number or string), or the raw value if not encrypted.
 *
 * Gracefully handles:
 * - Encrypted JSON envelopes (auto-decrypt)
 * - Raw encrypted strings (auto-decrypt)
 * - Plaintext values (pass through)
 * - null/undefined (return as-is)
 */
export function decryptField(
  stored: unknown,
): string | number | null {
  if (stored == null) {
    return null;
  }

  // If it's an encrypted envelope object
  let obj = stored as Record<string, unknown>;
  if (typeof stored === 'string') {
    try {
      obj = JSON.parse(stored) as Record<string, unknown>;
    } catch {
      // Not JSON, treat as plaintext
      return stored;
    }
  }

  // Check if it's an encrypted envelope
  if (
    obj &&
    (obj as unknown as EncryptedEnvelope).__enc === true
  ) {
    const envelope = obj as unknown as EncryptedEnvelope;
    const plain = decrypt(envelope.c, envelope.iv, envelope.t);

    // Try to parse as number
    const num = Number(plain);
    return isNaN(num) ? plain : num;
  }

  // Not encrypted, return as-is
  return stored as string | number;
}

export type { EncryptionConfig, EncryptedEnvelope, EncryptResult };
