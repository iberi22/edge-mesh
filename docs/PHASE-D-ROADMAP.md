# Phase D — Deprecación limpia (roadmap)

**Estado:** iniciada 2026-07-17 (CI + plan); extracción Maloca y “p2p sin PeerJS” **no** se hacen en este PR por riesgo de regresión.

## D1 — Reducir p2p-mesh-core

**Hoy:** `p2p-mesh-core` sigue siendo el dueño de:

- PeerJS + PQC handshake (ML-KEM/ML-DSA)
- `YJS_UPDATE` / branch filter / retries
- Roles, recovery, authority messages

**Target:**

```
p2p-mesh-core → shelf-domain (types, dbSync maps, business rules)
edge-mesh     → transport + identity + authz + envelopes
Shelf app     → wiring only
```

**Pasos sugeridos (sesión futura):**

1. Mover `P2PManagerTransport` a `@shelf/edge-mesh-adapters` o `edge-mesh/adapters/shelf`
2. Extraer handshake PQC a `edge-mesh/identity` o package `edge-mesh-pqc`
3. Reemplazar `YJS_UPDATE` por `EDGE_MESH_ENVELOPE` tipo SYNC con feature flag
4. Dejar `p2pManager` como thin wrapper o eliminarlo

## D2 — Maloca fuera del core

**Hoy en `edge-mesh/src`:**

- `maloca/*` (kernel, karma, evidentia, gateway…)
- `adapters/maloca-salud|veeduria|xavier`

**Target package:** `@edge-mesh/maloca` (o monorepo workspace separado).

**Bloqueadores de seguridad a resolver al mover:**

| Issue | Path |
|-------|------|
| `evidentia.verify()` always `true` | `src/maloca/evidentia.ts` |
| JWT secret hardcodeado | `src/maloca/gateway/auth.ts` |

**Pasos:**

1. Crear package con exports de maloca + adapters
2. Core `index.ts` deja de re-exportar maloca (breaking; major version)
3. Shelf **no** debe depender de maloca

## D3 — Hardened + CI

| Item | Estado |
|------|--------|
| CI GitHub Actions standalone | ✅ `.github/workflows/ci.yml` |
| Coverage gates | ❌ pending |
| Features maturity `hardened` | ❌ (integrated partial) |
| Monorepo vitest install | ❌ `@vitest/utils` roto / junctions stale |

## SSOT policy (crítico)

Hay **dos copias** de edge-mesh:

1. `E:\proyectosSWAL\edge-mesh` — standalone (preferido para core multi-app)
2. `E:\proyectosSWAL\shelf\packages\edge-mesh` — monorepo package

Además se detectó junction de node_modules apuntando a:

`E:\scripts-python\shelf\packages\edge-mesh` (ruta legacy)

**Regla:** editar en standalone → copiar a monorepo package → `pnpm install` para reparar links. No editar solo dist.
