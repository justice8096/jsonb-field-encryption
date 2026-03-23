---
name: jsonb-field-encryption
description: AES-256-GCM field-level encryption for JSON/JSONB database columns
version: 0.1.0
---

# JSONB Field Encryption Skill

Use this skill when the user needs to encrypt sensitive fields within JSON objects stored in databases (PostgreSQL JSONB, MongoDB documents, etc.).

## When to use
- User needs field-level encryption for database records
- User wants to encrypt specific fields in JSON objects (not entire rows)
- User mentions PII protection, HIPAA, or data-at-rest encryption for individual fields
- User is working with Prisma middleware for encryption

## How to use

```typescript
import { encryptField, decryptField, createPrismaMiddleware } from 'jsonb-field-encryption';

// Encrypt a single field value
const encrypted = encryptField('sensitive-data', encryptionKey);
// Returns: { __enc: true, c: '...', iv: '...', t: '...' }

// Decrypt
const original = decryptField(encrypted, encryptionKey);

// Prisma middleware (auto-encrypt/decrypt specified fields)
prisma.$use(createPrismaMiddleware({
  key: process.env.ENCRYPTION_KEY,
  models: {
    User: ['ssn', 'dateOfBirth', 'bankAccount'],
    HealthRecord: ['diagnosis', 'medications']
  }
}));
```

## Key behaviors
- AES-256-GCM with unique IV per field encryption
- JSON envelope format: `{ __enc: true, c: ciphertext, iv: initVector, t: authTag }`
- Graceful passthrough — already-encrypted fields are not double-encrypted
- Non-encrypted fields pass through untouched
- Prisma middleware for automatic encrypt-on-write / decrypt-on-read
- TypeScript with full type definitions
