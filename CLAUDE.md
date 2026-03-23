# JSONB Field Encryption

## Purpose
Application-layer AES-256-GCM encryption for sensitive data stored in database JSONB columns. Provides field-level encrypt/decrypt with a JSON envelope format, graceful passthrough when no key is configured, and startup validation.

## Tools & Stack
- **TypeScript** with Node.js crypto module
- No external dependencies

## Directory Structure
```
src/
  index.ts               — Main exports
  encryption.ts          — encrypt, decrypt, encryptField, decryptField
  types.ts               — TypeScript interfaces
tests/
  encryption.test.ts     — Encrypt/decrypt, passthrough, envelope tests
```

## Key Commands
```bash
npm test
npm run build
```

## API
```typescript
import { encrypt, decrypt, encryptField, decryptField } from 'jsonb-field-encryption';

// Field-level (for JSONB storage)
const stored = encryptField(42);       // '{"__enc":true,"c":"...","iv":"...","t":"..."}'
const value = decryptField(stored);     // 42

// Raw encrypt/decrypt
const { ciphertext, iv, tag } = encrypt('sensitive data');
const plain = decrypt(ciphertext, iv, tag);
```

## Environment
```
ENCRYPTION_MASTER_KEY=<64 hex chars>   # 32-byte key
```

## Technical Notes
- AES-256-GCM with 96-bit random IV per encryption
- JSON envelope: `{ __enc: true, c: ciphertext, iv: iv, t: authTag }`
- Graceful passthrough when no key is set (stores plaintext, warns once)
- Production startup validation warns if key is missing
- decryptField auto-detects encrypted vs plaintext values
