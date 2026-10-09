# Shared Professional Record — Data Model

> **Status:** design document. No code. Nothing here is implemented.
> **Scope:** what a medical node shares with a peer, what stays private, and why the
> four layers are kept apart. Protocol lives in [`protocolo.md`](./protocolo.md);
> network rules live in [`reglas-red.md`](./reglas-red.md).

---

## 0. The one distinction this whole model rests on

`nodoId` already exists in the repo and it is **cryptographically strong**:

- `derivarNodoId(kemPublico)` in `src/identity/index.ts` returns
  `mlkem<32 hex chars>` — the first 16 bytes of a domain-separated
  `SHA-256("shelf-edge-mesh/v1/nodo-id" || kemPublico)`.
- `crearIdentidadVinculada()` makes the id *be* the hash of the key the node must
  present to prove possession. `evaluarVinculoNodoId()` returns `conflicto` when a
  claimed derived id does not match the presented key.

That guarantees **anti-impersonation of a key**. It guarantees **nothing whatsoever
about whether the key holder is a physician**. Anyone can run `generateKeypair()`.

So the model is four layers, and the most common design error in this kind of system
is collapsing them into one "user" object:

| # | Layer | What it proves | Who asserts it | Can it be forged? |
|---|-------|----------------|----------------|-------------------|
| 0 | `nodoId` | I control a key, and nobody else controls this id | mathematics | no |
| 1 | `CredencialMedica` | this human holds license L in country C, valid until D | the state / the college | **yes** — anyone can write one |
| 2 | `Aval` | *I* checked layer 1 and stand behind it | a peer node | only by compromising a peer key |
| 3 | `Karma` | peers have repeatedly endorsed me over time | the sum of peers | no (bounded, decaying) |

**Access is granted by layer 1 + layer 2. Never by layer 0, never by layer 3.**
Layer 0 is required to *carry* the claim and is worthless as evidence of merit.

---

## 1. What exactly is a professional node

A node is **not** a person. It is a keypair bound to one credential claim at a time.
The record has two halves:

### 1.1 The cryptographic half (already in the repo)

```ts
// Conceptual, NOT the wire format. See src/identity/index.ts for the real types.
interface Nodo {
  nodoId: NodoId;              // 'mlkem' + 32 hex, derived from the KEM key
  pubKeyFirma: ParPublico;     // ML-DSA-65  (exportarPublico)
  kemPublico: ParPublico;      // ML-KEM-768  (exportarKemPublico)
  algoritmoFirma: 'ML-DSA-65';
  vinculo: 'vinculado' | 'heredado';   // evaluarVinculoNodoId()
  primeraVez: number;          // RegistroConfianzaClaves.primeraVez
  rotaciones: number;          // explicit rotations only
}
```

### 1.2 The professional half (new — this document)

```ts
interface RegistroProfesional {
  version: 1;
  nodoId: NodoId;                    // binding: which key this claim rides on
  credenciales: CredencialMedica[];
  especialidades: Especialidad[];
  avalRecibido: ResumenAvales;       // aggregate, see §4
  declaracion: DeclaracionNodo;      // who operates the node, jurisdiction
}
```

### 1.3 The rule that keeps a node from being a person

**One human may legitimately run several nodes** (a private clinical node and a public
teaching node are different trust surfaces). Therefore:

- We never store `nodoId → person` as a fact we assert.
- We store `idLicencia` (§2.2), which *is* per-human, and the anti-sybil rules in
  `reglas-red.md` are built on `idLicencia`, not on `nodoId`.
- A node may **rotate** its keypair. `RegistroConfianzaClaves.rotarClavePublica()` is the
  only path that may replace pinned keys, and because `nodoId` is derived from the
  **KEM** key, a rotation necessarily changes the `nodoId`. Key rotation is therefore
  **auditable, not silent** — this is already a documented property of the repo
  (`identityFromSecret`, `conKem`). The medical layer must treat a `nodoId` change on a
  known physician as a **new node requiring re-validation of layer 1**, never as a
  continuity.

---

## 2. Credentials

### 2.1 Reusing the OrionHealth pattern

`apps/OrionHealth/lib/features/doctor_verification/domain/services/license_verifier.dart`
already solves "is this license number real" with the right primitive:

```dart
final normalized = licenseNumber.replaceAll(RegExp(r'\s+'), '').toUpperCase();
final hash = sha256.convert(utf8.encode(normalized)).toString();
final countryHashes = await _registry.getHashesForCountry(countryCode);
if (countryHashes.isEmpty) return LicenseVerificationResult.unknown;
if (countryHashes.contains(hash)) return LicenseVerificationResult.valid;
return LicenseVerificationResult.invalid;
```

Three properties of this pattern we must keep:

1. **Only the hash ever travels.** The license number itself is never broadcast. The
   number is PII under Ley 1581/2012 and is not needed by peers.
2. **Country-scoped registries.** A license is only meaningful against the authority
   that issued it. Colombia (ReTHUS / Ministerio de Salud), Spain (Colegio Oficial de
   Médicos), etc. are different datasets with different update cadences.
3. **Three-valued, not boolean.** `valid | invalid | unknown`.

### 2.2 Two gaps in that pattern that the mesh MUST close

These are defects *for our use case*, not for OrionHealth's local-lookup use case:

- **`unknown` is not `valid`.** An empty country registry yields `unknown`. In a mesh
  that lets a node self-attest, treating `unknown` as "unverified but proceed" would
  open a hole where an *unsupported country* is a bypass. **Rule: `unknown` ⇒
  `NO_VERIFICADO`.** Access stays closed. This is the fail-closed default.
- **`expired` is declared but never returned.** The enum has `expired` and the function
  never produces it — a hash membership list carries no validity window. In a mesh that
  goes on for years, an immutable hash-set membership means **a license cancelled in
  2027 still verifies forever**. The credential record must therefore carry its own
  expiry *signed by the issuer*, not inferred from list membership (§2.3).

### 2.3 The credential record

```ts
interface CredencialMedica {
  id: string;                    // stable: hash(idLicencia + tipo + pais)
  tipo: 'licencia' | 'especialidad' | 'colegiacion' | 'registro_rethus';
  pais: string;                  // ISO 3166-1 alpha-2: 'CO' | 'ES' | ...
  autoridad: string;             // 'minsalud-rethus', 'colomedico-cm', ...
  idLicencia: string;            // sha256(normalized) — public-safe
  numeroLicenciaCifrado: Uint8Array;  // sealed to the verifier; optional, see §5
  especialidad?: string;         // 'medicina_general', 'cardiologia', ...
  emitidoEn: number;
  vigenteHasta: number;          // MUST come from the issuer's signature, not a list
  estadoEmision: 'autofirmada' | 'anclada_autoridad' | 'atestiguada_pares';
  // Proof = ML-DSA-65 over canonical bytes of everything above, except `firma`.
  firma: Uint8Array;
  emisor: NodoId;                // 'autofirmada' ⇒ emisor === sujeto
}
```

`estadoEmision` is the honest label of how the credential was obtained, and it is what
peers read:

- **`autofirmada`** — the node signed its own claim. This is a *format-valid
  assertion by an anonymous party*. It carries **zero** evidential weight. Useful only
  for the initial handshake so a peer knows what to go and check.
- **`atestiguada_pares`** — N peers each independently verified it and signed an `Aval`.
  This is the state that actually opens access.
- **`anclada_autoridad`** — the state's or the college's own key signed it. Strongest,
  and the only state that survives peers going offline.

### 2.4 Specialties and collegiate registration

`especialidad` is a separate `CredencialMedica` with `tipo: 'especialidad'` and its own
`vigenteHasta`. Specialties expire and are revoked differently from the base license.
Never model specialty as a boolean field on the license: a boolean cannot expire.

The product promise is "**certified** doctors". A certified doctor is
`licencia ∧ especialidad`, both with `estadoEmision: 'atestiguada_pares' | 'anclada_autoridad'`,
both unexpired. A licensed-but-unspecialized doctor is a legitimate node with a
*different and lower* capability set — this is a product decision, see
`DECISIONES` §A.4.

---

## 3. Why a hashed registry snapshot is the only honest anchor

The requirement is "nobody confers the license". That is not fully achievable, and the
design should say so plainly rather than imply otherwise.

**A signature proves authorship, never truth.** ML-DSA-65 over a claim proves the
claimer wrote it. It cannot prove the Ministry of Health agrees. The network's real
anchor is therefore a **replicated, verifiable reference dataset**: a per-country set of
license hashes. This is the same primitive as OrionHealth's registry, moved from a local
table into something peers gossip and cross-check.

That still means a reference exists. What changes:

- it is **append-only and hash-compared**, so tampering is detectable;
- it is **replicated**, so no single node's copy is load-bearing;
- peers compare **hashes**, so the reference leaks nothing per-doctor (see §6).

This is the design's central honest trade: **a peer-to-peer network of physicians cannot
be reference-free.** The goal is not "no authority"; it is "no *single* authority, and
every claim traceable to who checked it". If the owner wants a genuinely
authority-free network, the only remaining option is peer-attestation-only with no
registry at all — which raises the cost of `atestiguada_pares` and is a real decision
(see `DECISIONES` §B.1).

### 3.1 The `idLicencia` as Sybil cost — and its privacy price

Publishing `idLicencia` publicly has two consequences that pull in opposite directions
and must both be stated to the owner:

- **It is the anti-Sybil primitive.** Ten nodes claiming to be ten doctors all present
  the same `idLicencia` ⇒ provably one human. Detection is trivial and free.
- **It is a tracking identifier.** Anyone holding the mesh can ask "which nodes present
  this `idLicencia` over time, and when were they online?" That is a de-anonymization
  vector for a small professional community, and in a country where a physician's
  patient roster is itself sensitive, movement patterns are a real risk.

Proposed mitigation (needs owner sign-off): a **grace alias** — during the onboarding
window a node may present under an ephemeral derived id and a per-application
`idLicencia` commitment (salt chosen by the applicant), publishing the unsalted
`idLicencia` only when it publishes its first `Aval`. Before publication, cross-node
dedup uses the commitment, which reveals nothing until someone with the license number
(and therefore the salt) checks it.

---

## 4. Endorsement (`Aval`) — and how it differs from an appointment

An `Aval` is a **peer assertion about a claim**. It must be structurally incapable of
being confused with anything else.

```ts
interface Aval {
  id: string;                     // ${avalador}:${avalado}:${timestamp}:${nonce}
  version: 1;

  // ── WHO ──
  avalador: NodoId;               // signed this
  avalado: NodoId;                // about this node

  // ── WHAT IS BEING ENDORSED ── (not a free-text opinion)
  objetoAval: 'licencia_verificada' | 'especialidad_verificada'
             | 'interaccion_clinica' | 'docencia';
  credencialRef: string;          // id of the CredencialMedica
  hashCredencial: string;         // binds the aval to exact credential bytes

  // ── HOW THE AVALADOR CHECKED IT ── (this is the field that carries meaning)
  metodoVerificacion:
    | { clase: 'registro_por_pais'; pais: string; versionRegistro: string; }
    | { clase: 'colegio_directo'; ref: string; }        // out-of-band, college
    | { clase: 'testimonio_directo'; }                   // "I have worked with them"
    | { clase: 'supervision'; desde: number; hasta: number; };

  evidenciaHash: string;          // hash of the artifact relied upon, if any
  alcance: 'permanente' | 'anual';   // annual ⇒ must be renewed, feeds decay
  emitidoEn: number;
  vigenteHasta: number;
  revocable: true;                // always. See protocolo.md §5
  firma: Uint8Array;              // ML-DSA-65 by avalador
}
```

### 4.1 What makes it an aval and not a cita (appointment)

The distinction is not cosmetic; conflating them destroys the anti-Sybil property.

| | `Aval` | `Cita` / `interaccion` |
|---|---|---|
| Direction | peer → node (about a *claim*) | patient → node (about an *encounter*) |
| Subject of the assertion | a credential hash | a fact of a real encounter |
| `metodoVerificacion` | how the checker verified | none needed |
| Requires reciprocity | no | no |
| Counts toward `atestiguada_pares` | `licencia_verificada` only | **never** |
| Requires a human who was present | no | yes |

**Rule: only `objetoAval: 'licencia_verificada'` (and `'especialidad_verificada'`)
can promote a credential to `atestiguada_pares`.** An `Aval` of
`interaccion_clinica` proves the claimer treated patients, not that they are licensed.
Allowing clinical `Aval`s to count toward credential verification is precisely the hole
that lets a well-liked non-doctor into a network of doctors.

### 4.2 `metodoVerificacion` is not decoration

Two `Aval`s with the same subject but different methods must be weighted differently,
and a peer should be able to see *why* it is trusting someone:

- `registro_por_pais` — cheap, anyone can do it, reproducible offline, but only as fresh
  as the snapshot. **`versionRegistro` is mandatory** so a stale snapshot is visible.
- `colegio_directo` — expensive, rare, and the only method that survives the registry
  being wrong. This is what a founding cohort should hold.
- `testimonio_directo` — cheap and unfalsifiable. Good signal of collegiality, **weak
  signal of licensure.** Must be weighted below registry checks.
- `supervision` — time-bounded, non-symmetric (A supervises B ⇒ B's aval of A is not
  symmetric evidence), and the strongest peer signal because it implies sustained
  observation.

### 4.3 Symmetry and collusion

- `avalador === avalado` is refused, exactly as `applyTransaction` already refuses it
  with `MotivoRechazo = 'auto_emision'` in `src/maloca/karma.ts`. **The same rule,
  copied, for `Aval`.**
- A reciprocal pair (A avals B and B avals A on the same day) should be flagged
  `aval: 'reciproco_sospechoso'` and **not count double** toward the threshold.
- Collusion beyond pairs (a clique of ten) is **not solvable in this design** and must
  be stated as a residual risk, not mitigated by a heuristic. See `DECISIONES` §C.4.

---

## 5. What is encrypted in transit, what is not — and why

### 5.1 The criterion

**Encrypt anything a peer must not read to *decide*. Leave cleartext anything a peer
must read to *verify*.** If verification required decryption, the network becomes a
blind relay and verification becomes a timing side channel.

| Field | Wire | Why |
|---|---|---|
| `nodoId`, `tipo`, `version`, `nonce`, `timestamp` | **clear** | envelope structure; `canonicalEnvelopeBytes` in `src/protocol/index.ts` signs exactly these |
| `idLicencia` (hash) | **clear** | the anti-Sybil primitive needs to be comparable across nodes (§3.1) |
| `pais`, `autoridad`, `especialidad`, `vigenteHasta`, `estadoEmision` | **clear** | a peer must be able to *refuse* without decrypting; opaque fields would force a round trip per check |
| `metodoVerificacion`, `versionRegistro`, `hashCredencial` | **clear** | the reason for trust must be auditable, not sealed |
| `numeroLicenciaCifrado` | **sealed** | real-world PII; nobody in the mesh needs it |
| display name, contact, bio, clinic address | **sealed** | directory-level PII, opt-in |
| `Aval.firma` | **clear** | `verifyEnvelopeSignature` / `KarmaManager.verify` must run on it |
| patient clinical data | **never on the mesh** | see below |

The sealing mechanism already exists: `encapsular()` / `decapsular()` /
`derivarClaveSimetricaDesde()` in `src/identity/index.ts` give an ML-KEM-768 shared
secret that `derivarClaveSimetrica()` turns into a 32-byte AEAD key. A medical field
sealed to a specific recipient's KEM key is a direct reuse of that path.

### 5.2 Envelope metadata leakage — an accepted limitation, documented

Encryption here is **payload** encryption. The `Envolvente` in
`src/types/index.ts` is
`{ id, tipo, origen, destino, timestamp, firma, payload, version, nonce }`, and
**every one of those fields travels in the clear by construction** — they are inside
the signed canonical bytes and must be, for `verifyEnvelopeSignature` to work.

Consequently an observer on the path sees:

- **who** is talking (`origen`, `destino` — both full `nodoId`s, i.e. linkable across
  sessions because the id is a stable key hash, §1.1);
- **when**, to millisecond precision (`timestamp`);
- **how much**, to within a padding granularity (`payload` length);
- **how often**, and therefore the rhythm of a clinical relationship.

And the PeerJS transport (`src/transport/peerjs.ts`) negotiates `peerId`, `host`, `port`
and `path`, so the **signalling broker sees the peer id and the connection timing**
even when the payload is sealed.

This is **not a bug to be fixed in this layer.** It is the price of a signed, linkable,
non-repudiable envelope, and it is the same trade every instant-messaging system makes.
It is documented here so that nobody later "fixes" it by removing signatures, which
would trade a metadata leak for a total loss of accountability.

Mitigations worth considering, none of which are strong, and none of which should be
promised to the owner as privacy: fixed-cadence padding to bucket message sizes,
batching, and mixing traffic across namespaces so a single doctor's schedule is not
visible. **Anonymity is not achievable over this transport and is not claimed.**

### 5.3 Patient data is out of scope by construction

The network shares **the physician's professional record**, never the patient's. This is
not a policy preference; it is the only defensible position:

- Health data is a **special category** under GDPR Art. 9. Under **Ley 1581/2012
  Art. 5** it is sensitive, and **Art. 2(a)**'s household/personal exemption is lost the
  moment it is shared with a third party — which every peer node is.
- A mesh is a **replication substrate** (`src/op-log/index.ts`, `src/snapshot/index.ts`,
  `src/sync/engine.ts`). Anything written to it is designed to be copied and kept. A
  patient's record inside an OpLog that peers retain is a breach waiting for a payload
  bug, and no amount of per-envelope encryption helps once five nodes hold the cleartext.
- **AI Act (EU) 2024/1689 Art. 53(1)(d):** the open-source exemption does **not** cover
  the summary of training data. Any model trained on network content carries the
  obligation with it.

Consequences, stated as hard design rules:

1. `RegistroProfesional` has **no field capable of holding patient data**. Not "we won't
   populate it" — the shape does not admit it.
2. `Aval` of `objetoAval: 'interaccion_clinica'` asserts *"a real encounter occurred"*.
   It carries **no date, no diagnosis, no content**. It is a boolean with a signer.
3. Any future feature needing patient-adjacent data (referrals, continuity of care)
   requires a **different transport with different storage rules**, not a field added here.

---

## 6. A credential's full lifecycle as data

```
        nodo generates keypair
                  │
                  ▼
        ┌─────────────────────┐
        │ CredencialMedica    │  estadoEmision: 'autofirmada'
        │ idLicencia + hash   │  ← NO access. Only says "go check me".
        └──────────┬──────────┘
                   │  peers fetch country registry snapshot
                   │  OrionHealth pattern: normalize → sha256 → contains()
                   ▼
        ┌─────────────────────┐
        │ Aval × N            │  metodoVerificacion: 'registro_por_pais'
        │ (independent check) │  firmadas por pares, nunca por el sujeto
        └──────────┬──────────┘
                   │  threshold met → estadoEmision: 'atestiguada_pares'
                   ▼
        ┌─────────────────────┐
        │ ACCESO CONCEDIDO    │  authz: NamespaceAuthorizer.concederCapacidad()
        │ por credencial,     │  NOT by getScore()
        │ no por karma        │
        └──────────┬──────────┘
                   │  expiry, or a peer revokes its Aval
                   ▼
        ┌─────────────────────┐
        │aval retirado →      │  see protocolo.md §5: the signature is eternal,
        │ 'atestiguada' pierde│  only the endorsement is revocable
        └─────────────────────┘
```

The threshold constant is borrowed from `src/maloca/karma.ts`: `DELTA_MAX_ABS = 25`
exists precisely so that "reaching a score of 100 takes at least 4 independent
endorsers". The same arithmetic should size the `Aval` threshold — **the number must be
chosen so that no single compromised peer can promote a credential alone.**

---

## 7. Relationship to what already exists in the repo

| Need | Reuse | Path |
|---|---|---|
| keypair, node id derivation, rotation audit | `PostQuantumIdentity`, `derivarNodoId`, `evaluarVinculoNodoId` | `src/identity/index.ts` |
| key pinning, TOFU, explicit rotation | `RegistroConfianzaClaves` | `src/identity/index.ts` |
| payload sealing to one recipient | `encapsular`/`decapsular`/`derivarClaveSimetricaDesde` | `src/identity/index.ts` |
| canonical bytes for signing | `canonicalStringify` pattern, `canonicalEnvelopeBytes` | `src/maloca/karma.ts`, `src/protocol/index.ts` |
| self-endorsement refusal | `auto_emision` check | `src/maloca/karma.ts` |
| bounded influence, decay | `DELTA_MAX_ABS`, `applyDecay` | `src/maloca/karma.ts` |
| capability grant + expiry | `NamespaceAuthorizer.concederCapacidad` (default 24 h) | `src/authz/index.ts` |
| signed envelope transport | `createEnvelope`/`signEnvelope`/`validateEnvelope` | `src/protocol/index.ts` |
| license verification primitive | `LicenseVerifier.verify` | `apps/OrionHealth/.../license_verifier.dart` |
| new message types | `TIPO_MENSAJE` needs a `CREDENCIAL` / `AVAL` entry | `src/types/index.ts` — **not edited by this task** |

---

## DECISIONES QUE NECESITAN DEL DUEÑO

**A. Modelo y alcance**

- **A.1** — ¿El `idLicencia` sin sal se publica desde el primer día, o se aplica el
  *grace alias* de §3.1? Sin sal: anti-Sybil trivial y rastreo del médico. Con sal:
  privacidad y un bypass de deduplicación antes de la publicación.
- **A.2** — ¿El `RegistroProfesional` se replica a **todos** los nodos (legible por
  cualquiera que esté en la red) o se consulta **bajo demanda** solo al par que valida?
  Lo primero hace la red verificable offline y expone el directorio profesional completo.
- **A.3** — ¿El número de licencia cifrado se guarda **alguna vez**, o se descarta tras
  la verificación? Guardarlo permite re-verificar y mantiene el ancla del colegio; descartarlo
  reduce el PII a cero pero deja de poder reemitir.
- **A.4** — ¿Un médico con licencia válida **sin** especialidad entra a la red? Propuesta:
  sí, con menos capacidades. Si se decide que no, la red se reduce a un directorio de
  especialistas y el problema de cold-start empeora.
- **A.5** — ¿El nombre real del médico es público por defecto u **opt-in**? Afecta
  revisión pública y el Lex Artis (secreto profesional), no solo privacidad.

**B. Ancla de confianza**

- **B.1** — ¿La red opera **solo** con `atestiguada_pares` (sin registry snapshots), o se
  exige además una **firma del colegio** (`anclada_autoridad`) para las especialidades? Lo
  segundo divide la red en dos capas y probablemente la deja vacía en el lanzamiento.
- **B.2** — ¿Se invierte en obtener acceso real a los portales oficiales (ReTHUS en
  Colombia, Consejo Colegios en España) para snapshots firmados y fechables, o se arranca
  con snapshots aportados por los nodos y auto-versionados? Lo primero es un proyecto de
  meses con un burócrata.
- **B.3** — ¿Umbral de `Aval` para `atestiguada_pares`? Propuesta 4 (misma aritmética que
  `DELTA_MAX_ABS`). Si sube, cold-start; si baja, un solo par comprometido basta.

**C. Privacidad y cumplimiento**

- **C.1** — ¿Mercado inicial: **solo Colombia**, o **Colombia + UE/España** desde el día
  uno? El marco de datos cambia por completo (ReTHUS vs EUDI Wallet) y mantener ambos a
  la vez duplica el trabajo de registries.
- **C.2** — ¿Existe una **entidad legal** detrás? Sin ella la Ley 1581 (ley de
  protección de datos personales) tiene un responsable que no es nadie, y el
  cumplimiento de la UE exige una figura clara.
- **C.3** — ¿Se acepta y se **documenta públicamente** que el tráfico tiene metadatos
  visibles (§5.2), o hay que reducir el `timestamp`/tamaño antes del lanzamiento público?

**D. Alcance técnico**

- **D.1** — ¿Los `Aval` son firmados con la **misma** clave ML-DSA-65 del nodo, o el
  diseño exige una **segunda clave** dedicada a avalar (para poder rotarla por separado)?
  Rotar la clave de aval no debería invalidar las conversaciones firmadas.
- **D.2** — ¿`interaccion_clinica` se emite en v1, o se pospone? Es el que más código y
  el que más riesgo de confundir con un aval de licencia exige.