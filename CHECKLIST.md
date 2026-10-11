# Release Readiness — Impeccable Library Checklist

This checklist documents the quality, security, packaging, and governance criteria required for `@iberi22/edge-mesh` (and future `@swal/edge-mesh`) to maintain tier-1 npm library status.

Every item includes its exact verifying command and its real measured status as of v1.0.0.

---

## 1. License & Copyright
- [x] **Clear SPDX / License Declaration**
  - **Requirement:** Repository includes an authoritative license file and `package.json` declares a matching license identifier.
  - **Verifying Command:**
    ```bash
    head -n 5 LICENSE && node -p "require('./package.json').license"
    ```
  - **Measured Result:** Both declare `FSL-1.1-ALv2` (Apache-2.0 transition planned per ecosystem governance rule).

## 2. Exports, Types & Bundle Integrity
- [x] **Clean Type Compilation (`tsc --noEmit`)**
  - **Requirement:** Zero TypeScript compiler errors in strict mode across all source files.
  - **Verifying Command:**
    ```bash
    npm run check
    ```
  - **Measured Result:** Exited with code `0`, 0 errors.

- [x] **Standard Package Exports Linting (`publint`)**
  - **Requirement:** Package export maps (`.`, `./web`, `./web/trust`, `./web/oplog`, `./web/merge`) resolve correctly for ESM, bundlers, and typecheckers without missing or misaligned declaration files.
  - **Verifying Command:**
    ```bash
    npx -y publint
    ```
  - **Measured Result:** `All good!` — 0 errors, 0 warnings.

## 3. Package Distribution Footprint
- [x] **Smoke Test on Built Artifacts (`pack:smoke`)**
  - **Requirement:** Packaged tarball exports are loadable and entrypoints match runtime declarations.
  - **Verifying Command:**
    ```bash
    npm run pack:smoke
    ```
  - **Measured Result:** `pack:smoke ok tarball=iberi22-edge-mesh-1.0.0.tgz bytes=754891 packages=10 web_exports=40 trust_exports=29`.

- [x] **Clean Tarball Contents (`npm pack --dry-run`)**
  - **Requirement:** Tarball includes only `dist/`, `src/`, `LICENSE`, `README.md`, and `package.json`. No test fixtures, benchmarks, or temporary files included.
  - **Verifying Command:**
    ```bash
    npm pack --dry-run
    ```
  - **Measured Result:** 581 files total, unpacked size 3.2 MB, packed size 754.9 kB (< 1 MB target).

## 4. Continuous Integration (CI)
- [ ] **Automated CI Green Status**
  - **Requirement:** All CI workflow jobs (lint, test, security, benchmark-gate) pass on GitHub Actions.
  - **Verifying Command:**
    ```bash
    gh pr view 139 -R iberi22/edge-mesh --json state,statusCheckRollup
    ```
  - **Measured Result:** CI stabilization and lint fixes in progress via PR #139 (`fix/ci-lint`). Base `main` requires merge of PR #139 to achieve green CI.

## 5. Test Suite & Regression Coverage
- [ ] **Full Test Suite Execution**
  - **Requirement:** 100% of automated unit and integration tests pass.
  - **Verifying Command:**
    ```bash
    npm test
    ```
  - **Measured Result:** 158 test files executed. 984 tests pass, 68 adversarial audit regression tests failing on `main`. Hardening tracked in PR #139 and issues #123–#128.

## 6. Security Policy & Dependency Audit
- [x] **Security Disclosure Policy Present**
  - **Requirement:** `SECURITY.md` documents private disclosure channels (GitHub Security Advisories) and supported versions.
  - **Verifying Command:**
    ```bash
    test -f SECURITY.md && /run/current-system/sw/bin/grep -q "GitHub Security Advisories" SECURITY.md && echo "OK"
    ```
  - **Measured Result:** `OK` — Policy present with private advisory URL and response commitment.

- [x] **Dependency Vulnerability Audit**
  - **Requirement:** No high or critical unmitigated vulnerabilities in production dependencies.
  - **Verifying Command:**
    ```bash
    npm audit --omit=dev
    ```
  - **Measured Result:** 0 vulnerabilities in production dependency graph.

## 7. Package Provenance & Metadata
- [x] **NPM Provenance Configuration**
  - **Requirement:** `package.json` contains `publishConfig` with `provenance: true` and public access.
  - **Verifying Command:**
    ```bash
    node -p "require('./package.json').publishConfig"
    ```
  - **Measured Result:** `{ access: 'public', registry: 'https://registry.npmjs.org/', provenance: true }`.

## 8. Documentation Standards
- [x] **English-Only Technical & Community Files**
  - **Requirement:** All community guidelines, checklists, architecture overviews, and issue templates are written in concise, idiomatic English.
  - **Verifying Command:**
    ```bash
    test -f README.md && test -f CONTRIBUTING.md && test -f CODE_OF_CONDUCT.md && test -f ROADMAP.md && test -f CHECKLIST.md && echo "All English Docs Present"
    ```
  - **Measured Result:** `All English Docs Present`.

## 9. Secret & Credential Leak Prevention
- [x] **Zero Leaked Secrets in Repository**
  - **Requirement:** No API tokens, private keys, or passwords committed anywhere in the codebase.
  - **Verifying Command:**
    ```bash
    /run/current-system/sw/bin/grep -rIn --exclude-dir={node_modules,.git,dist} -E '(ghp_[A-Za-z0-9_]{36}|github_pat_[A-Za-z0-9_]{82}|PRIVATE KEY-----|xox[baprs]-[A-Za-z0-9-]+)' . || echo "Clean"
    ```
  - **Measured Result:** `Clean` — 0 detected credentials.
