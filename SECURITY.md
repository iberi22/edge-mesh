# Security Policy — Edge Mesh

SouthWest AI Labs (SWAL) takes security seriously. `@iberi22/edge-mesh` incorporates post-quantum cryptographic primitives to protect peer-to-peer data transmission, identity verification, and state synchronization against present and future threats.

---

## Supported Versions

Only the latest release and main branch of `@iberi22/edge-mesh` receive security updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

---

## Post-Quantum Cryptography Architecture

- **Identity Signatures:** ML-DSA-65 (FIPS 205 compliant) implemented via `@noble/post-quantum`.
- **Key Exchange:** ML-KEM-768 key encapsulation mechanism for establishing encrypted AEAD channels.
- **Symmetric Cipher:** AES-256-GCM (`EncryptedChannel`) derived via SHA-256 HKDF.
- **Replay Defense:** 30-second strict validity window with nonce deduplication (`seenNonces`).

---

## Reporting a Vulnerability

If you discover a potential security vulnerability within `@iberi22/edge-mesh`:

1. **Do NOT open a public issue.**
2. Send an email or private report detailing:
   - Nature of the vulnerability.
   - Steps or proof-of-concept script to reproduce the issue.
   - Impact assessment (e.g., identity spoofing, key leak, denial of service).
3. The SWAL security team will acknowledge receipt within 48 hours and provide updates regarding resolution and patched releases.
