# FEATURE: feat-ivn-proofs — E2E Encrypted Identity Proofs

**Status:** `planned` | **Issue:** edge-mesh#95
**Design:** `docs/SWAL/IDENTITY_VERIFICATION_NETWORK.md` §2 (IVN-2)

## Overview

Pruebas de identidad cifradas E2E multi-recipient: el solicitante sube sus pruebas (redes,
documentos) cifradas con ML-KEM-768 para CADA validador elegido. Solo los validadores pueden
descifrar; el veredicto es público pero las pruebas NUNCA.

## Alcance (IN SCOPE)

| ID | Entregable | DoD (verificable) |
|----|-----------|-------------------|
| IVN-2-01 | `src/namespaces/ivn-proofs.ts` — `uploadProof(applicantKey, validatorKeys[], payload)` cifra por validador (multi-recipient ML-KEM-768) | `grep -c "ml_kem768\|encapsulate\|decapsulate" src/namespaces/ivn-proofs.ts` >= 2 |
| IVN-2-02 | `decryptProof(validatorKey, requestId)` — solo el validador dueño descifra | test: otros NO pueden |
| IVN-2-03 | `getProofMetadata(requestId)` — hash/tamaño/count, NUNCA contenido | test: metadata sin payload |
| IVN-2-04 | Firma ML-DSA-65 del solicitante sobre hash del payload (integridad + no-repudio) | `grep -c "verify\|sign" src/namespaces/ivn-proofs.ts` >= 2 |
| IVN-2-05 | Namespace `swal/ivn/proofs/{requestId}` | `grep -c "swal/ivn/proofs" src/namespaces/ivn-proofs.ts` >= 1 |
| IVN-2-06 | Export en `src/namespaces/index.ts` | build OK |
| IVN-2-07 | `test/ivn-proofs.test.ts` — 5 validators, cada uno descifra su copia, otros no | `npx vitest run test/ivn-proofs.test.ts 2>&1 | grep "passed"` |

## Fuera de alcance (OUT OF SCOPE)

- Selección de validadores → IVN-1 (xavier#1380)
- API/storage → IVN-3 (xavier#1382)
- Karma → IVN-4 (xavier#1381)

## Condiciones de ENTREGA (DoD — TODAS obligatorias)

1. [ ] `cd cores/edge-mesh && npm run build` — 0 errors
2. [ ] `npx vitest run test/ivn-proofs.test.ts` — passed
3. [ ] `wc -l src/namespaces/ivn-proofs.ts` >= 60
4. [ ] `wc -l test/ivn-proofs.test.ts` >= 35
5. [ ] `git show HEAD --name-only | grep -cE "src/|test/"` >= 1
6. [ ] PR contiene >= 1 archivo (`.files | length` >= 1)
7. [ ] NO nuevas deps (ML-KEM-768 ya en @noble/post-quantum)
8. [ ] Metadata NUNCA contiene contenido (test lo verifica)

## Verification harness

```bash
cd /home/belal/proyectosSWAL/cores/edge-mesh
npm run build
npx vitest run test/ivn-proofs.test.ts
```

## Anti-hallucination

- READ before write: `pqc-handshake.ts` FULLY (API de ML-KEM-768 en @noble/post-quantum)
- Multi-recipient: encapsular UNA vez POR validador (no reusar ciphertext)
- KISS: in-memory map + test (storage real en IVN-3)
- No tocar pqc-handshake/identity/encrypted-plugin · features.json al final
