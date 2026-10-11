# Security Policy

SouthWest AI Labs (SWAL) takes the security of Edge Mesh seriously. Edge Mesh incorporates post-quantum cryptographic primitives to safeguard decentralized peer-to-peer data replication, peer identity, and CRDT state synchronization.

---

## Supported Versions

Only the latest active release series receives security updates and vulnerability patches.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0.0 | :x:                |

---

## Cryptographic Security Model

- **Digital Signatures:** ML-DSA-65 (FIPS 204 compliant post-quantum lattice signature scheme).
- **Key Encapsulation:** ML-KEM-768 hybrid key encapsulation with ECDH P-256 for forward-secure ephemeral channels.
- **Symmetric AEAD:** AES-256-GCM authenticated encryption for session traffic.
- **Replay Protection:** Bounded monotonic validity windows with deduplicated message tracking.

---

## Reporting a Vulnerability

We request that all security vulnerabilities be reported privately. **Please do NOT report security vulnerabilities through public GitHub issues or public forum channels.**

### Preferred Method: GitHub Security Advisories
Please submit security reports directly via GitHub Security Advisories:
[Submit Private Security Advisory](https://github.com/iberi22/edge-mesh/security/advisories/new)

### Alternative Method: Email
If you are unable to use GitHub Advisories, email the security team at:
`security@southwestailabs.org`

### What to Include
To help us triage and resolve the issue quickly, please include:
- A clear description of the vulnerability and its potential impact.
- Steps to reproduce or a minimal proof of concept (PoC).
- Affected version(s) and environment details.
- Any suggested mitigations or patches, if available.

### Disclosure & Response Process
1. **Acknowledgment:** We will acknowledge receipt of your report within 48 hours.
2. **Assessment:** Our security team will assess the report and confirm the vulnerability.
3. **Remediation:** We will develop and test a fix in a private branch or advisory fork.
4. **Coordinated Release:** A patched release will be published alongside a security advisory acknowledging your contribution (unless you request anonymity).
