# Contributing to Edge Mesh

Thank you for contributing to Edge Mesh! We welcome contributions to help build a robust, secure, and decentralized peer-to-peer mesh.

---

## Code of Conduct

All contributors and participants are expected to adhere to our [Code of Conduct](./CODE_OF_CONDUCT.md).

---

## Development Setup

Prerequisites: Node.js >= 22.0.0 and npm.

```bash
# Clone the repository
git clone https://github.com/iberi22/edge-mesh.git
cd edge-mesh

# Install dependencies
npm install

# Build the TypeScript project
npm run build

# Run type checking
npm run check

# Run tests
npm test

# Run linter
npm run lint
```

---

## Architectural Principles

1. **Single Source of Truth:** `@iberi22/edge-mesh` is the authoritative core library for mesh networking and P2P CRDT sync across the ecosystem.
2. **Post-Quantum Cryptography Preservation:** Do not weaken cryptographic primitives (ML-DSA-65 signatures, ML-KEM-768 hybrid encapsulation, AES-256-GCM).
3. **Local-First & Zero Vendor Lock-in:** Code and protocols must remain open and operational without mandatory centralized servers or SaaS dependencies.
4. **UI Agnostic:** Core mesh capabilities remain completely detached from specific frontend frameworks.

---

## Contribution Workflow

1. **Issues:** Open an issue or join an existing discussion before starting major architectural changes.
2. **Branching:** Create a feature branch off `main` (e.g., `feat/topic`, `fix/issue-description`, `docs/topic`).
3. **Testing:** Every change must include unit or integration tests verifying the behavior.
4. **Formatting & Linting:** Ensure code passes `npm run check` and `npm run lint`.
5. **Conventional Commits:** Use clear commit messages following Conventional Commits (e.g., `feat(web): add loopback latency simulation`, `fix(sync): prevent off-by-one boundary drop`).
6. **Pull Requests:** Open a pull request against `main`. Ensure all CI checks pass and complete the pull request template.
