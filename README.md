# jsonb-field-encryption

AES-256-GCM field-level encryption for sensitive data in JSONB columns.

## Use Case

Store sensitive financial or personal data in PostgreSQL JSONB columns with transparent encryption. Data is encrypted at rest and automatically decrypted on retrieval.

**Example:** Encrypt customer salary, SSN, or bank account fields in a JSONB object.

## Features

- **AES-256-GCM** encryption with random IVs and authentication tags
- **Field-level** — encrypt individual fields, not entire rows
- **Framework-agnostic** — works with Prisma, TypeORM, Drizzle, plain queries
- **Graceful fallback** — stores plaintext if no key configured (dev mode)
- **JSON envelope** — stores encrypted data as `{ __enc: true, c, iv, t }`
- **Type-safe** — TypeScript support included

## Installation

```bash
npm install jsonb-field-encryption
```

Or with Yarn/PNPM:

```bash
yarn add jsonb-field-encryption
pnpm add jsonb-field-encryption
```

## Configuration

Set your encryption key in the environment:

```bash
# 32 bytes = 64 hex characters
export ENCRYPTION_MASTER_KEY="e1f2c3a4b5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0"
```

Or pass it programmatically:

```typescript
import { validateEncryptionConfig } from 'jsonb-field-encryption';

validateEncryptionConfig({
  masterKey: process.env.ENCRYPTION_MASTER_KEY,
});
```

Generate a random key:

```bash
# macOS/Linux
openssl rand -hex 32

# Windows PowerShell
$bytes = [byte[]]::new(32); (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($bytes); [BitConverter]::ToString($bytes) -replace '-'
```

## Usage

### With Prisma Middleware

```typescript
import { encryptField, decryptField } from 'jsonb-field-encryption';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

// Middleware to auto-encrypt/decrypt sensitive fields
prisma.$use(async (params, next) => {
  // Encrypt on write
  if (
    (params.action === 'create' || params.action === 'update') &&
    params.model === 'Customer'
  ) {
    if (params.data.financialData?.ssn) {
      params.data.financialData.ssn = encryptField(
        params.data.financialData.ssn,
      );
    }
  }

  const result = await next(params);

  // Decrypt on read
  if (params.action === 'findMany' || params.action === 'findUnique') {
    if (result.financialData?.ssn) {
      result.financialData.ssn = decryptField(result.financialData.ssn);
    }
  }

  return result;
});

// Usage
const customer = await prisma.customer.create({
  data: {
    name: 'Alice',
    financialData: {
      ssn: '123-45-6789', // Auto-encrypted by middleware
      salary: 100000,
    },
  },
});
```

### Manual Encryption/Decryption

```typescript
import {
  encrypt,
  decrypt,
  encryptField,
  decryptField,
} from 'jsonb-field-encryption';

// Low-level: encrypt and decrypt values
const { ciphertext, iv, tag } = encrypt('sensitive-data');
const plaintext = decrypt(ciphertext, iv, tag);

// High-level: field encryption for JSONB
const encrypted = encryptField('user-ssn-123-45-6789');
// Returns: '{"__enc":true,"c":"base64...","iv":"base64...","t":"base64..."}'

const decrypted = decryptField(encrypted);
// Returns: "user-ssn-123-45-6789"

// Numeric values auto-convert
const encryptedNum = encryptField(12345);
const decryptedNum = decryptField(encryptedNum);
console.log(typeof decryptedNum); // 'number'
```

### Raw SQL Queries

```typescript
import { encryptField, decryptField } from 'jsonb-field-encryption';

// Encrypt before inserting
const encrypted = encryptField('customer-ssn');

await db.query(
  `UPDATE customers SET data = jsonb_set(data, '{ssn}', $1) WHERE id = $2`,
  [encrypted, customerId],
);

// Decrypt after retrieving
const row = await db.query(
  `SELECT data->>'ssn' as ssn FROM customers WHERE id = $1`,
  [customerId],
);

const plaintext = decryptField(row.rows[0].ssn);
```

## API Reference

### `encrypt(plaintext: string | number): EncryptResult`

Encrypt a value. Returns `{ ciphertext, iv, tag, passthrough? }`.

- **passthrough** is true if encryption is disabled (no key configured)

### `decrypt(ciphertext: string, iv: string, tag: string): string`

Decrypt a value. Returns the plaintext.

### `encryptField(value: string | number | null | undefined): string | null`

Encrypt a field for JSONB storage. Returns a JSON string representing the encrypted envelope, or null if input is null/undefined.

### `decryptField(stored: unknown): string | number | null`

Decrypt a field from JSONB storage. Handles encrypted envelopes, raw strings, and plaintext. Returns null if input is null/undefined.

### `isEncryptionEnabled(): boolean`

Check if encryption is active (master key configured).

### `validateEncryptionConfig(config?: EncryptionConfig): void`

Validate and set encryption configuration at startup. Logs warnings in production if key is missing.

```typescript
interface EncryptionConfig {
  masterKey?: string | null;
  enabled?: boolean;
  algorithm?: string;
}
```

## Encryption Details

- **Algorithm**: AES-256-GCM (NIST-approved, provides confidentiality + authenticity)
- **IV**: 96-bit random nonce (recommended for GCM)
- **Key derivation**: None (use a cryptographically random 32-byte hex key)
- **Tag**: 128-bit authentication tag (included in ciphertext validation)

## Security Considerations

- **Key management**: Store the encryption key in a secrets manager (AWS Secrets Manager, Vault, etc.), not in code
- **Rotation**: To rotate keys, you'll need to decrypt all data with the old key and re-encrypt with the new key
- **Integrity**: GCM mode provides both encryption and authentication
- **Passthrough mode**: When no key is configured, plaintext is stored. Use in development only.

## Performance

- Encryption/decryption is fast (microseconds per field)
- No additional database round-trips
- Works efficiently with Prisma middleware (minimal overhead)

## Testing

```bash
npm test
```

Tests use a known key (`a`.repeat(64)) and validate:
- Round-trip encryption/decryption
- Numeric value handling
- Null/undefined handling
- Plaintext passthrough when encryption disabled

## Limitations

- No built-in key rotation
- Ciphertext is non-deterministic (random IV) — same plaintext encrypts differently each time
- Cannot query encrypted fields directly in SQL (decrypt first, or use deterministic encryption if needed)

## License

MIT © 2026 Justice
