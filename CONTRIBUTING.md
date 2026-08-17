# Contributing to Edge Mesh

Thank you for your interest in contributing to `@iberi22/edge-mesh`! We welcome contributions from developers, researchers, and open-source enthusiasts.

---

## Code of Conduct & Core Directives

1. **Monorepo SSOT Policy:** `@iberi22/edge-mesh` is the Single Source of Truth for core mesh logic. Never copy-paste core files into consumer repos; import `@iberi22/edge-mesh` or work within this monorepo workspace.
2. **Post-Quantum Cryptography:** Do not weaken post-quantum cryptographic primitives (ML-DSA-65 / ML-KEM-768).
3. **No Commercial Paywalls / Third-Party Lock-in:** Code and documentation must remain open and free without Centralized SaaS dependencies or hidden paywall/stripe requirements.

---

## Development Workflow

### 1. Prerequisites & Setup

Ensure you have Node.js 22+ installed.

```bash
# Clone repository
git clone https://github.com/iberi22/edge-mesh.git
cd edge-mesh

# Install workspace dependencies
npm install

# Build core library
npm run build
```

### 2. Running Tests

All changes must pass unit and integration tests.

```bash
# Run all Vitest test suites
npm test

# Run tests in watch mode
npm run test:watch
```

---

## Pull Request Guidelines

1. **Branch Naming:** Create a feature or bugfix branch with a descriptive name (`docs-standard-...`, `feat/...`, `fix/...`).
2. **File Islands:** Respect file islands. Documentation changes should not touch source code files unless explicitly required.
3. **Commit Messages:** Follow conventional commits (e.g., `docs: align edge-mesh docs to SWAL standard`, `feat: add post-quantum handshake fallback`).
4. **Licensing:** All contributions are subject to the [Contributor License Agreement (CLA)](./CLA.md) and distributed under the [AGPL-3.0-only License](./LICENSE).
