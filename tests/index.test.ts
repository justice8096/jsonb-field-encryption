/**
 * Tests for jsonb-field-encryption.
 */

import { test } from 'node:test';
import assert from 'node:assert';
import {
  encrypt,
  decrypt,
  encryptField,
  decryptField,
  isEncryptionEnabled,
  validateEncryptionConfig,
} from '../src/index';

test('encrypt and decrypt round-trip', () => {
  // Set a test key
  validateEncryptionConfig({
    masterKey: 'a'.repeat(64), // 32 bytes in hex
  });

  const plaintext = 'sensitive-data-123';
  const encrypted = encrypt(plaintext);

  assert(encrypted.ciphertext !== plaintext);
  assert(encrypted.iv);
  assert(encrypted.tag);
  assert(!encrypted.passthrough);

  const decrypted = decrypt(
    encrypted.ciphertext,
    encrypted.iv,
    encrypted.tag,
  );

  assert.strictEqual(decrypted, plaintext);
});

test('encryptField returns JSON envelope', () => {
  validateEncryptionConfig({
    masterKey: 'b'.repeat(64),
  });

  const encrypted = encryptField('test-value');
  assert(typeof encrypted === 'string');

  const obj = JSON.parse(encrypted!);
  assert.strictEqual(obj.__enc, true);
  assert(obj.c); // ciphertext
  assert(obj.iv);
  assert(obj.t); // tag
});

test('decryptField handles encrypted envelope', () => {
  validateEncryptionConfig({
    masterKey: 'c'.repeat(64),
  });

  const plaintext = 'field-value-456';
  const encrypted = encryptField(plaintext);

  const decrypted = decryptField(encrypted);
  assert.strictEqual(decrypted, plaintext);
});

test('decryptField handles numeric values', () => {
  validateEncryptionConfig({
    masterKey: 'd'.repeat(64),
  });

  const value = 12345;
  const encrypted = encryptField(value);

  const decrypted = decryptField(encrypted);
  assert.strictEqual(decrypted, value);
  assert(typeof decrypted === 'number');
});

test('encryptField returns plaintext when encryption disabled', () => {
  validateEncryptionConfig({
    masterKey: null,
  });

  const plaintext = 'no-encryption';
  const result = encryptField(plaintext);

  assert.strictEqual(result, plaintext);
});

test('decryptField passes through plaintext', () => {
  validateEncryptionConfig({
    masterKey: null,
  });

  const plaintext = 'unencrypted-value';
  const result = decryptField(plaintext);

  assert.strictEqual(result, plaintext);
});

test('decryptField handles null/undefined', () => {
  assert.strictEqual(decryptField(null), null);
  assert.strictEqual(decryptField(undefined), null);
});

test('isEncryptionEnabled reflects configuration', () => {
  validateEncryptionConfig({
    masterKey: 'e'.repeat(64),
  });
  assert(isEncryptionEnabled());

  validateEncryptionConfig({
    masterKey: null,
  });
  assert(!isEncryptionEnabled());
});

test('different keys produce different ciphertexts', () => {
  validateEncryptionConfig({
    masterKey: 'f'.repeat(64),
  });
  const encrypted1 = encrypt('data');

  validateEncryptionConfig({
    masterKey: 'g'.repeat(64),
  });
  const encrypted2 = encrypt('data');

  assert.notStrictEqual(
    encrypted1.ciphertext,
    encrypted2.ciphertext,
  );
});
