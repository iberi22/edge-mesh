# Credential Verification Protocol — Verifying a Node Without a Central Authority

> **Status:** design document. No code.
> **Companion:** [`modelo-datos.md`](./modelo-datos.md) defines the records referenced
> here; [`reglas-red.md`](./reglas-red.md) defines what the resulting trust permits.

---

## 1. The problem, stated without a comforting answer

"Verify a physician with no central authority" contains a hidden premise. To know that
license `L` is real, someone must already know that `L` is real. If nobody knows, nobody
can say. If one node knows, that node is an authority whether it calls itself one or not.

So the design question is not "how do we eliminate authority". It is:

> **How do we make every claim traceable to a named set of peers who each checked it,
> and make the check cheap enough to re-run?**

Everything below follows from that.

---

## 2. W3C VC 2.0 and the EUDI Wallet — viability verdict

### 2.1 What the standards actually say

- **W3C VC Data Model v2.0 reached W3C Recommendation on 15 May 2025** (seven documents,
  including Data Integrity and Bitstring Status). So it is a settled standard, not a
  draft.
- **Reg. (EU) 2024/1183 (EUDI Wallet)** is the legal instrument. Its architecture
  requires attestations to carry everything needed for **validity status checks** and to
  use **holder binding** (key/device binding via SD-JWT VC or ISO 18013-5), with
  **selective disclosure** of attributes and OpenID4VCI/4VP presentation flows.
- Relying parties **register** with a Member State; issuers are **audited**; wallets are
  **certified** by Member States.

### 2.2 The decisive structural mismatch

Read the ARF requirements carefully and one fact dominates: **the EUDI model presupposes
a Trust List of certified issuers.** A (Q)EAA is only meaningful because a Relying Party
resolves the issuer's key against an official list and checks status against an official
source. Remove the issuer registry and a (Q)EAA becomes an unsigned claim by an anonymous
party — precisely the `estadoEmision: 'autofirmada'` state that
`modelo-datos.md` §2.3 already rates as carrying zero evidential weight.

The standard's strongest property, **holder binding**, is also the one we already have
and already use better than the standard requires: our `nodoId` *is* a hash of the KEM key
that must be presented to prove possession (`derivarNodoId`,
`evaluarVinculoNodoId` → `conflicto` on mismatch). That is a strictly stronger
key-binding story than a generic SD-JWT nonce, because the identifier itself is
unforgeable.

And **selective disclosure is a product risk, not a feature, for a doctor directory.**
Disclosing "is a physician in Colombia" without disclosing *which* physician defeats
anti-Sybil (§3.1 of the data model): a Sybil ring runs ten nodes that each prove "some
licensed Colombian physician exists" and each are the same human.

### 2.3 Verdict

| Question | Verdict |
|---|---|
| Adopt W3C VC 2.0 wholesale | **No.** Its value is issuer-registry-based verification, which is precisely what a Sybil-hard peer network cannot obtain, and it adds JSON-LD/context machinery to a TypeScript mesh that already has canonical bytes. |
| Adopt EUDI Wallet flows | **No, not in v1.** Requires certified issuers, Member State registration, audited issuers, `mdoc`/`OpenID4VP`. A multi-year public-sector programme. |
| Borrow **holder binding** | **Already superseded.** Our derived `nodoId` is stronger and already implemented. |
| Borrow the **three-part credential decomposition** (claim / proof / status) | **Yes.** It is the cleanest framing of what we independently arrived at, and it separates "what is claimed" from "who stands behind it" from "is it still current". |
| Borrow **status lists** concept | **Yes, in our own form.** Revocation of an *endorsement* (§5) is a status problem, not a signature problem. |
| Aim for **EUDI compatibility later** | **Yes, as a v3 goal.** The `anclada_autoridad` credential state is the designed entry point. It costs nothing extra now to keep `autoridad` as a first-class field. |

**Honest position:** our network is *less* verifiable than an EUDI wallet and that is the
correct trade for Sybil-resistance. We should not describe it as "EUDI-compliant" or
"blockchain-verified credentials" in marketing. It is: *self-attested claims, independently
re-checked by named peers, with signed reasons and revocable endorsements.*

---

## 3. First contact — why TOFU is insufficient here

The repo already has TOFU: `RegistroConfianzaClaves.registrarClavePublica()` pins keys on
first sight, throws `ConflictoClavePublicaError` on mismatch, and only accepts changes
through explicit `rotarClavePublica()`.

**TOFU binds a key. It does not bind a license.** After TOFU completes, the network knows
"this id is this key forever". It knows *nothing* about whether a physician sits behind
it. Concretely, an attacker who has completed TOFU with the network is permanently
trusted *as a key holder* while remaining entirely unverified as a professional. TOFU
alone makes impersonation of an *existing node* hard and impersonation of the
*profession* trivial.

**Therefore: TOFU terminates at layer 0 and must never be read as credentialing.**
Onboarding is a second, separate, explicit state machine that a node must be *promoted
through*, and no amount of peer connection performs that promotion automatically.

### 3.1 The two-key bootstrap (trust vs. profession)

The flow below assumes one design decision worth defending: **TOFU pinning and
credential verification are different ceremonies with different failure modes, and must
not share a trigger.** Connecting to a peer pins a key. Claiming to be a physician
requires presenting a credential and collecting independent `Aval`s. A node that fails
the second keeps the first; it is simply not a physician, and it stays in the mesh as a
non-credentialed peer if useful (see `reglas-red.md`).

---

## 4. The full flow

### Phase 0 — key generation (already exists)

```
generateKeypair()                       src/identity/index.ts
  → ML-DSA-65 signing pair
  → ML-KEM-768  KEM pair
derivarNodoId(kemPublico)               → 'mlkem' + 32 hex
crearIdentidadVinculada()               → nodoId IS the hash of its own KEM key
```

### Phase 1 — first contact (TOFU; already exists)

```
A announces itself to B
B: RegistroConfianzaClaves.registrarClavePublica(A.nodoId, A.pubKeyFirma, A.kemPublico)
   ├─ unknown id  → pin, accept          (TOFU)
   └─ known id, different key
        → throw ConflictoClavePublicaError   → REJECT (impersonation)
```

After this, B trusts the **key** and nothing else. B is not yet permitted to treat A as
a physician.

### Phase 2 — credential presentation

```
A → B : payload CredencialMedica { idLicencia, pais, autoridad, especialidad,
                                    vigenteHasta, estadoEmision, firma }
```

B performs, in this order (cheap first, PQC last — the same ordering discipline
`applyTransaction` in `src/maloca/karma.ts` uses so a malformed message never costs a
PQC operation):

| # | Check | Failure ⇒ |
|---|---|---|
| 1 | `validateEnvelope()` — shape | drop |
| 2 | `MessageDeduplicator.esDuplicado()` — replay | drop |
| 3 | `evaluarVinculoNodoId(nodoId, kemPublico)` | **reject node**, not just message |
| 4 | `verificarNodoIdVinculado` / TOFU conflict | reject |
| 5 | `canonicalEnvelopeBytes` + `verifyEnvelopeSignature()` | drop |
| 6 | `Date.now() < vigenteHasta` | `no vigente`, access closed |
| 7 | `pais` registry available? | **`unknown` ⇒ `NO_VERIFICADO`**, fail closed |
| 8 | OrionHealth `sha256(normalize(licencia))` ∈ country set | invalid |
| 9 | Credential id not already attested to a *different* node | **Sybil alarm** (§6) |

Step 9 deserves emphasis: two nodes presenting the same `idLicencia` are **the same
human**, and this is detectable and free. The protocol must treat it as a hard signal,
not a heuristic.

### Phase 3 — peer validation

Each peer B independently ran steps 1–9 and, if satisfied, emits an `Aval`:

```
B → mesh : Aval {
  avalador: B, avalado: A,
  objetoAval: 'licencia_verificada',
  credencialRef, hashCredencial,      ← binds to exact credential bytes
  metodoVerificacion: { clase:'registro_por_pais', pais, versionRegistro },
  alcance: 'anual', revocable: true,
  firma: ML-DSA-65 by B
}
```

Rules enforced per peer, mirroring `KarmaManager.applyTransaction`:

- `avalador !== avalado` — self-endorsement refused (`auto_emision`).
- `hashCredencial` must match the exact credential bytes B actually checked.
- The `Aval` is **idempotent per `id`**, so a replayed `Aval` from the OpLog cannot be
  counted twice.
- A credential whose bytes changed invalidates every `Aval` bound to the old hash.

### Phase 4 — threshold and promotion

```
count(distinct avaladores with objetoAval='licencia_verificada')
  ≥ UMBRAL  →  credencial.estadoEmision := 'atestiguada_pares'
```

UMBRAL must satisfy the `DELTA_MAX_ABS` arithmetic: sized so **no single compromised peer
can promote a credential alone**. See `modelo-datos.md` §6 and DECISIÓN B.3.

Only then:

```
NamespaceAuthorizer.concederCapacidad(espacio, nodoId, capacidad, expiracionMs, firma)
```

**Note what decides access: the credential state, never `KarmaManager.getScore()`.**
Grants expire on their own (`EXPIRACION_POR_DEFECTO_MS = 24 h`) and are re-issued from
the credential's current state, so lapse is the default.

### Phase 5 — ongoing

- Credentials are re-verified on an `anual` cadence (`Aval.alcance`), producing a fresh
  signed statement with a fresh registry `versionRegistro`.
- `KarmaManager.applyDecay` handles standing; `namespace` grants handle capability.
- Any peer may revoke its own `Aval` at any time (Phase 6).

---

## 5. Revocation — the honest version

### 5.1 What is impossible

**A published ML-DSA-65 signature cannot be un-published.** It is a permanent fact: that
key signed those bytes, and anyone who stored the bytes still holds proof. A registry
that later removes the license does not and cannot make the signature stop existing.
Anyone designing a "revocation" that pretends otherwise is describing something that
cannot be built.

### 5.2 What is actually revocable

The protocol's security does not rest on the signature — it rests on the **aggregate
`atestiguada_pares` state**. That is revocable because it is a *fold over live
endorsements*, not a stored fact. This is why the data model separates "credential
bytes" (immutable, eternal) from "endorsement" (revocable, expiring):

| Layer | Revocable? | Mechanism | Residual |
|---|---|---|---|
| The `nodoId` ↔ keypair binding | **No** | — | TOFU rotation is auditable, never silent |
| A credential's signature | **No** | — | eternal; harmless once unsupported (§5.3) |
| A credential's *registry membership* | **Yes** | snapshot version + `vigenteHasta` | stale snapshots lie; mitigated by `versionRegistro` |
| **An `Aval`** | **Yes** | the avalador publishes a revocation signed by the same key | requires the peer to receive the revocation |
| **`atestiguada_pares` state** | **Yes** | recomputed from live `Aval`s | convergence is the propagation layer's job |
| **A capability grant** | **Yes** | `NamespaceAuthorizer.revocarCapacidad()` + 24 h default expiry | — |

So the revocation record is a **signed negative statement about an endorsement**, in the
same shape as the positive one, verified with the same key:

```
AvalRevocacion { id, avalRef, avalador, avalaRevocado, motivo, emitidoEn, firma }
```

Accepted only if `avalador === avalador(original Aval)`. A node cannot revoke somebody
else's endorsement, and **cannot** revoke a rival's endorsement to gain advantage — which
means a malicious peer has a strictly limited weapon, one honest revocation at a time,
always public.

### 5.3 Why an eternal signature is not a leak

A revoked credential's bytes remaining on disk is **not** a confidentiality problem:
the credential is a license number hash, authority, specialty and dates. None of it is
patient data (patient data never enters this network — `modelo-datos.md` §5.3). It *is*
a mild privacy exposure (proof of former licensure) which is already public via ReTHUS
and the national colleges. **The design accepts this and documents it** rather than
pretending otherwise.

### 5.4 The revocation gap that must be owned

Revocation is only as fast as **propagation**. `src/maloca/karma.ts` already documents
that the class does not propagate reputation, so two nodes observing the same events hold
different scores until the replication layer lands. The same holds for `Aval`
revocations.

Therefore, until propagation exists:

- a revoked endorsement is **not globally effective**, and
- the honest guarantee is **"revocable by peers, eventually effective everywhere"**,
  not "revocable".

Two mitigations, both partial, both honest:

1. **Short grant TTLs.** `concederCapacidad` defaults to 24 h; for a high-sensitivity
   capability, minutes. Bounded blast radius without propagation.
2. **Direct notice to the counterparty** out-of-band when a revocation concerns a node
   the local node is actively connected to, rather than waiting for gossip.

**This is the single largest correctness gap in the design** and it is stated in the
design, not deferred to implementation. See DECISIÓN E.1.

---

## 6. Sybil at the protocol level

The credential flow makes it *detectable*, which is not the same as *prevented*:

- Ten nodes, one human ⇒ ten copies of the same `idLicencia` ⇒ trivially detected by any
  peer running step 9.
- Ten nodes, ten humans, one real physician ⇒ ten distinct `idLicencia`s ⇒ invisible at
  the protocol level. Only the resource-cost controls in `reglas-red.md` §2 apply.

**Detection is not prevention.** The protocol's contribution is to make the cheap attack
visible; the expensive attack (many real licensed people coordinating) is out of its
reach and is handled as governance.

---

## 7. New message types required

`TIPO_MENSAJE` in `src/types/index.ts` gained three members for this layer:

```ts
CREDENCIAL: 'credencial',          // presentation, request, response
AVAL: 'aval',                      // endorsement + revocation
REGISTRO: 'registro',              // country registry snapshot, hash-addressed
```

Reusing `TIPO_MENSAJE.AUTHZ` for credential traffic would be a mistake: authz grants are
*local capability* state, credentials are *replicated claims*, and conflating them makes
both unauditable.

---

## DECISIONES QUE NECESITAN DEL DUEÑO

**E. Protocolo y revocación**

- **E.1** — ¿Se acepta la brecha de propagación de revocación (§5.4) como coste de v1, o
  es bloqueante? Si es bloqueante, la capa de replicación deja de ser "next phase" y pasa
  a ser requisito de v1 — es un cambio grande de alcance y de cronograma.
- **E.2** — ¿`UMBRAL` de `Aval`? Propuesta 4 (misma aritmética que `DELTA_MAX_ABS = 25`).
  Si el dueño quiere 3, un solo par comprometido promueve una credencial.
- **E.3** — ¿Un `Aval` cuenta para siempre o caduca? El diseño propone cadencia `anual`
  (`alcance: 'anual'`). Con caducidad la red se auto-repara pero obliga a re-verificar;
  sin caducidad es más simple, pero un aval de 2019 sigue contando.
- **E.4** — ¿Quién puede **revocar** además del propio avalador? Propuesta: sólo el
  avalador, más una revocación de emergencia por quórum de pares (que es un poder
  fuerte y hay que decidir si existe).
- **E.5** — ¿`alerta_sybil` (mismo `idLicencia`, dos nodos) **suspende** automáticamente
  a ambos nodos, o **solo** notifica? Suspensión automática es fail-safe pero permite
  que un atacante malicioso pueda acusar a un tercero continuamente para silenciarlo.

**F. Estándares**

- **F.1** — ¿Se comunica la red como compatible con W3C VC 2.0 / EUDI Wallet? El diseño
  recomienda **no** hasta tener `anclada_autoridad`. ¿Está de acuerdo el dueño con esa
  contención en marketing?
- **F.2** — ¿Invertir desde ya en un adaptador EUDI (OpenID4VCI issuance) para poder
  lanzar en España sin rehacer? Es trabajo desperdiciado si el lanzamiento es Colombia-only.
- **F.3** — ¿Se publica un documento público de "qué garantiza y qué NO garantiza esta
  verificación" (el disclaimer de §2.3 elevado a política de producto)? Recomendación:
  sí, y adjuntarlo a la app.

**G. Alcance operativo**

- **G.1** — ¿Quién opera el primer registry snapshot por país? Hace falta **alguien** que
  lo firme y lo versione, o el `metodoVerificacion: 'registro_por_pais'` no es verificable
  por nadie.
- **G.2** — ¿TTL de `concederCapacidad` por defecto en la red médica? `authz/index.ts` usa
  24 h; para capacidades sensibles podría ser minutos. Trade-off: más renovaciones vs.
  menor ventana de exposición sin revocación propagada.
- **G.3** — ¿El rechazo de §4 paso 3 (`evaluarVinculoNodoId` conflicto) cierra el nodo o
  sólo el mensaje? Código actual distingue mal; la decisión es de política de red.