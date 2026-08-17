# Contributing to Edge Mesh & SWAL Network

Thank you for your interest in contributing to `@iberi22/edge-mesh` and the SouthWest AI Labs (SWAL) ecosystem! We welcome contributions from developers, researchers, and open-source enthusiasts.

For details on the overarching vision, strategic pillars, and architectural guidelines of the SWAL network, please refer to [docs/SWAL/GOAL.md](./docs/SWAL/GOAL.md).

---

## SWAL Ecosystem & Backlog Location

The overall SWAL ecosystem backlog and issue tracking across all modules are centrally coordinated via the **Maloca** hub:
- Global Ecosystem Backlog & Coordination: **Maloca** (`src/maloca/` / Maloca Backoffice)
- Single Source of Truth (SSOT) Core Library: `@iberi22/edge-mesh`

Before embarking on significant feature work, check the global backlog in Maloca and open an issue or proposal to discuss the scope with the team.

---

## Collaboration Workflow: Issue → PR → Merge (GitCore)

All contributions follow the standard SWAL GitCore workflow to ensure quality, security, and traceability:

1. **Issue Creation & Assignment:**
   - Create or select an issue tracking the desired feature or bug fix.
   - Align feature proposals with `.gitcore/features.json` schema v2 standards.

2. **Branching Strategy:**
   - Create a feature or bugfix branch off `main` with a clear prefix (e.g., `feat/...`, `fix/...`, `docs/...`, `hygiene/...`).

3. **Development & Testing:**
   - Write tests for new functionality using Vitest.
   - Run `npm run build` and `npm test` locally to confirm all tests pass.

4. **Pull Request & Code Review:**
   - Submit a Pull Request targeting `main`.
   - Ensure commit messages follow Conventional Commits standard (e.g., `docs: update CONTRIBUTING with SWAL guidelines`).

5. **Merge Policy:**
   - PRs must pass automated CI checks (linting, tests, security audit, and benchmark gates) before being merged into `main`.

---

## Code of Conduct & Core Directives

1. **Monorepo SSOT Policy:** `@iberi22/edge-mesh` is the Single Source of Truth for core mesh logic. Never copy-paste core files into consumer repos; import `@iberi22/edge-mesh` or work within this monorepo workspace.
2. **Post-Quantum Cryptography:** Do not weaken post-quantum cryptographic primitives (ML-DSA-65 / ML-KEM-768).
3. **No Commercial Paywalls / SaaS Lock-in:** Code and documentation must remain open and free without centralized SaaS dependencies or paywall requirements.

---

## Contributor License Agreement (CLA) & Licensing

All contributions are subject to the [Contributor License Agreement (CLA)](./CLA.md) and distributed under the [AGPL-3.0-only License](./LICENSE). By submitting a Pull Request, you agree to license your code under these terms.

---

## Prerequisites & Local Setup

```bash
# Clone repository
git clone https://github.com/iberi22/edge-mesh.git
cd edge-mesh

# Install workspace dependencies
npm install

# Build core library
npm run build

# Run unit and integration tests
npm test
```
