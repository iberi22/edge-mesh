# Network Rules — What Makes This Network Trustworthy

> **Status:** design document. No code.
> **Companion:** [`modelo-datos.md`](./modelo-datos.md), [`protocolo.md`](./protocolo.md).

---

## 1. Karma grants standing. Karma never grants access.

### 1.1 The separation, stated as an invariant

The repo already asserts this in prose, at
`src/maloca/karma.ts` lines 37–42:

> *"Karma is a signal, never a credential. Access to the medical network must be decided
> by the authz layer against a verified credential, never by comparing a karma number."*

This document turns that comment into the operational rule.

| | Karma decides | Credential decides |
|---|---|---|
| Node exists in the mesh | — | — |
| Can read public directory data | ✅ karma ≥ 0 | — |
| Can be listed as a physician | ❌ **never** | ✅ `atestiguada_pares \| anclada_autoridad` |
| Can be granted `write` in a clinical namespace | ❌ **never** | ✅ credential + explicit grant |
| Priority in peer selection | ✅ `getBestPeer()` | — |
| Can be trusted as a **peer reviewer** (`Aval`) | ✅ karma ≥ K_AVAL | ✅ credential unexpired |

### 1.2 Why the separation is not paranoia — it is load-bearing

If karma could grant access, then the cheapest attack in the entire system is to farm
reputation. And because a peer can already emit `TransaccionKarma` with any positive
`delta` up to 25 (see `DELTA_MAX_ABS`), reputation is **directly mintable** by anyone
willing to spend a few signatures. A network where reputation buys access is a network
where reputation is the attack surface.

The correct inversion: **reputation is earned cheaply and checked expensively.**
Standing determines who gets asked to review; the credential decides what that review is
worth and what the node may then do. A node with karma 0 and a valid license is a
legitimate doctor with low standing. A node with karma 1000 and no license is a
gossip amplifier with no professional standing whatsoever.

### 1.3 What karma *may* do (and it is not nothing)

Karma governs, and only governs:

1. **Priority** — `getBestPeer()` for work assignment.
2. **Review eligibility** — below `K_AVAL`, a peer may not emit `Aval`s.
3. **Rate limits** — via the existing `TokenBucketRateLimiter`
   (`src/security/rate-limiter.ts`): the token bucket is *keyed by karma tier*, so a
   karma-0 node is heavily throttled rather than cut off.
4. **Propagation effort** — how hard the node gossips, how many peers it keeps warm.

None of these is access. The distinction between 3/4 and access is exactly the boundary
the `auto_emision`, `delta_sobre_techo` and negative-delta refusals defend in
`applyTransaction`.

### 1.4 Negative deltas are already refused — do not "fix" that

`applyTransaction` rejects `delta <= 0` with `delta_no_positivo`, deliberately:
*"a targeted penalty is a griefing primitive (any peer could bury a competitor's
standing), so decay is the only path that lowers a score and it is uniform, gradual and
untargetable."*

**This is correct and must be preserved.** Any proposal to add "report a bad doctor → −10"
directly reintroduces a censorship primitive: a coalition of k nodes buries one competitor
at cost k. Standing falls only by uniform decay, and the behaviour a physician is upset
about is expressed through **revoking an `Aval`** (`protocolo.md` §5), which is honest
because a revoked endorsement is publicly attributable to the peer who revoked it.

---

## 2. Sybil resistance — and why PoW and PoS were rejected

### 2.1 The attack surface

Sybil = many identities, one attacker. In this network an attacker wants N nodes to
(a) look like N licensed doctors, or (b) obtain many `Aval`s and thereby
`atestiguada_pares` for a fake node, or (c) capture enough review weight to bury a
competitor or to inject a false `Aval`.

### 2.2 Why the standard answers are wrong here

**Proof of Work — rejected.**
The Sybil-resistance premise of PoW is *cost of sybil creation > cost of honest
participation*. For a clinical network this premise is inverted:

- Honest physicians are a **tiny, non-economic population**. Many of them are residents,
  specialists in public hospitals, or recently graduated — they will not burn CPU, and
  asking them to is asking them to spend money and battery on being allowed to practice
  digitally. The participation cost is borne by exactly the people the network exists to
  serve.
- The attacker here is not a spammer with a botnet but someone who **wants to impersonate
  a physician**. PoW makes creating an identity marginally expensive; it does nothing
  about the credential, which is the actual gate (§1).
- Mining on a phone that a physician carries in a pocket is a battery and a UX disaster,
  and patients pay the latency in the emergency path.

**Proof of Stake — rejected, and it is actively harmful here.**

- **It monetizes the Sybil attack.** A stake-based network requires stake to be
  *purchasable or slashable*. That converts a credential network into a financial market.
  Anyone with money can buy N identities; the only thing PoS guarantees is that the
  attacker's capital at risk scales with their balance sheet, which a well-funded actor
  accepts trivially.
- **Slashing is clinically inappropriate.** The penalty for misbehaviour is loss of
  stake. In a professional registry the meaningful consequence is loss of standing or
  loss of the ability to be reviewed — a reputational and administrative matter, decided
  by peers and colleges, not an economic one.
- **Karma already *is* a stake-like signal** and is deliberately non-transferable,
  non-purchasable, and **decaying**. `applyDecay` means standing earned once and never
  renewed cannot stand forever. That is the useful half of PoS, without the market.
- **Key custody becomes the attack.** PoS requires a validator to sign with a key that
  can be slashed. A physician's clinical signing key and a slasher-exposed consensus key
  in the same node is a catastrophic coupling: compromising a clinician's device for
  clinical data also destroys their network standing, or vice versa.

**Honest limitation:** because neither PoW nor PoS is used, this network's Sybil
resistance rests **entirely** on the credential layer. That is a real dependency and it
is stated rather than papered over. The network is only as Sybil-resistant as the license
registry it is anchored to.

### 2.3 What is used instead

| Mechanism | What it defends against | Where it lives |
|---|---|---|
| **Per-human `idLicencia` dedup** | N fake identities from one real doctor | `protocolo.md` §4 step 9; `modelo-datos.md` §3.1 |
| **Gated `Aval` emission** (`K_AVAL`) | a brand-new node bootstrapping itself into trust | §1.3 rule 2 |
| **`auto_emision` refusal** | self-endorsement | `src/maloca/karma.ts` `applyTransaction` |
| **`DELTA_MAX_ABS = 25`** | one peer moving a score across a threshold | `src/maloca/karma.ts` |
| **Bounded deltas + mandatory signature** | forged or replayed reputation | same |
| **Idempotent application per `tx.id`** | OpLog replay double-counting | same (`aplicadas` set) |
| **Uniform decay only** | targeted censorship | `applyDecay`; negative deltas refused |
| **Mutual-acknowledgement cost** | one attacker capturing one-sided trust | §2.4 |
| **Namespace capability grants, 24 h TTL** | standing leaking into access | `src/authz/index.ts` |

### 2.4 The honest Sybil gap

A patient who is one real human holding ten real licenses is not distinguishable from ten
licensed physicians, at any layer, and no rule in this document fixes it. What the
network *can* do is make each identity **cost an independent real-world anchor** — a real
license, checked by peers against a real registry. Making ten identities therefore costs
ten real licenses. That is the whole mechanism. It is weaker than PoW against a pure
economic attacker and it is the correct trade for a professional network, because it
attacks Sybil where Sybil actually lives: in the credential.

---

## 3. Review bombing and reputation manipulation

Two attacks, opposite directions, both real, both with different fixes.

### 3.1 Patient-side: defamatory review bombing

**Attack:** an adversary runs many patient identities to post many negative reviews against
a competitor, or buys them, and buries them.

**Why the obvious fix fails:** "require one review per patient" does nothing when the
patients are synthetic. This is the same Sybil problem in the review layer.

Mitigations, layered:

1. **Reviews are not access.** A negative review changes nothing about the license state.
   No `concederCapacidad` ever reads review sentiment. This is the single most important
   defence and it is structural: the product promise "reviews are public" is honoured
   *without* reviews being load-bearing.
2. **Reviews are attributed and signed.** A review carries the reviewer's `nodoId` and an
   ML-DSA-65 signature. Cheap anonymity is deliberately **not** offered: a reviewer who
   can hide cannot be sanctioned, and a reviewer who cannot be sanctioned can bomb.
3. **Reviewer eligibility.** Only a credentialed physician reviews physicians. A patient
   node's review is **not** a peer `Aval` and carries no threshold weight whatsoever
   (this is the hard rule in `modelo-datos.md` §4.1).
4. **Karma-weighted visibility.** Low-karma reviewers' reviews collapse by default and
   require expansion. This is presentation, not enforcement, and must be labelled as such
   in the UI or it becomes an invisible censorship mechanism.
5. **Per-reviewer rate limit** via `TokenBucketRateLimiter`, tiered by karma.
6. **Reverse-bombing defence:** a burst of reviews against one node within a short window
   is itself a signal, and raises the threshold for *promotion* on that node's credential
   until the burst decays. Never the reverse (never make it easier to bury someone).
7. **Rate-limited revocation:** a reviewer may revoke an `Aval` at most once per period
   per target, so revocation cannot itself be weaponised as a mass-burial tool.

### 3.2 Physician-side: buying patients

**Attack:** a physician buys synthetic positive reviews (and, worse, synthetic patient
interactions to generate them).

Why this is the more dangerous one: it is the attack that could produce a *false*
`atestiguada_pares`, i.e. it attacks the credential layer, not just the presentation.

Mitigations:

1. **Interaction is not endorsement.** `Aval` with `objetoAval: 'interaccion_clinica'`
   never counts toward `atestiguada_pares` (`modelo-datos.md` §4.1). **A physician
   cannot buy their way to licensure.** This is the load-bearing rule.
2. **`metodoVerificacion` is disclosed.** A `testimonio_directo` `Aval` states on its face
   that it is a colleague's word, not a registry check. Weighed accordingly
   (`modelo-datos.md` §4.2).
3. **The license anchor is external and non-fungible.** No amount of positive reviews
   substitutes for `sha256(normalize(licencia))` appearing in the country registry. Money
   cannot buy a government record.
4. **Reciprocal detection.** Simultaneous mutual `Aval`s are flagged
   `reciproco_sospechoso` and count once.
5. **Negative deltas stay refused.** So a coalition cannot simply vote a competitor down —
   they must withdraw their public, attributable `Aval`s instead, and every withdrawal is
   visible.

### 3.3 Collusion: the residual, unfixed risk

A clique of ten physicians mutually endorsing each other satisfies every rule in this
document and is still a clique. Symmetry checks catch pairs; time-window clustering hints
at cliques; nothing *proves* it. This design does **not** claim to solve collusion, and
no threshold on `Aval`s should be presented to the owner as doing so. The only real
mitigation is a registry anchor that does not depend on peers at all
(`anclada_autoridad`).

---

## 4. A node leaving the network

### 4.1 What it held, and who holds it now

| Data | Where it lived | Who keeps it after departure | Can it be recalled? |
|---|---|---|---|
| Own keypair | local device | nobody (destroyed) | n/a |
| Own `CredencialMedica` | local + replicated to peers | peers, indefinitely | **no** — §4.2 |
| `Aval`s it *received* | peers | peers | yes, by revoking each |
| `Aval`s it *emitted* | peers, and its own OpLog | peers | yes, via `AvalRevocacion` |
| Its `Karma` and full `historial` | every peer that saw its transactions | peers | no, but decays |
| **Patient clinical data** | **never on the mesh** | **nobody** | n/a — it was never there |
| Namespace capability grants | each holder's `NamespaceAuthorizer` | each holder | ✅ `revocarCapacidad()` |
| TOFU pin in the trust store | each peer's `RegistroConfianzaClaves` | each peer | ✅ `olvidar(nodoId)` |

The middle column is the uncomfortable one: **the network keeps a departed node's
endorsements and credentials.** That is a deliberate, documented consequence of a
replication substrate, and `modelo-datos.md` §5.3 is what keeps it acceptable — the
retained data is a license hash, a specialty and a set of dates, never patient data.

### 4.2 Departure procedure

1. **Voluntary and announced.** The node publishes a signed departure statement
   (`nodoId`, reason, timestamp, signature). Peers verify it against the pinned key.
2. **Emit revocation for every `Aval` it issued.** A clean departure means the node's
   attestations do not keep counting on its behalf after it is gone. This is why the
   `Aval` is revocable and why the credential bytes alone are not load-bearing.
3. **Peers revoke their TOFU pin** via `RegistroConfianzaClaves.olvidar(nodoId)` and
   revoke capability grants via `NamespaceAuthorizer.revocarCapacidad()`.
4. **Its `Karma` is left to decay** rather than zeroed — zeroing by fiat is the targeted
   penalty that `applyTransaction` refuses to allow, and it would also let a departure be
   weaponised as a griefing tool against a competitor.
5. **Retained records persist.** `Aval`s already received by peers are **not** deleted;
   deleting replicated history to satisfy a departure request would let any node erase
   evidence of its own past misbehaviour.

### 4.3 Unannounced departure (key compromise, seizure, abandonment)

The hard case. The protocol cannot distinguish "left" from "lost the device".

| Situation | Response | What still works |
|---|---|---|
| Graceful departure (§4.2) | full, prompt, attributable | everything |
| Node silent, `vigenteHasta` not reached | nothing immediate; grants lapse on their 24 h TTL | credential valid, network degraded |
| Node silent past `vigenteHasta` | credential lapses; `atestiguada_pares` recomputes | peers' `Aval`s of the license still stand |
| Node's key compromised | peers `olvidar()` the pin; **cannot** invalidate its old signatures | past `Aval`s it signed remain — **this is the accepted cost of §4.3's eternal signature** |
| Node's license actually revoked by the state | registry snapshot version bumps; `idLicencia` leaves the set | access closes at the next snapshot — **the only path that works without the peer** |
| Malicious node floods before going dark | rate limits + karma decay bound its standing | other nodes unaffected |

The uncomfortable truth, stated plainly: **the network cannot revoke a compromised key's
history.** A clinician whose laptop is stolen can have their past attestations used
against them indefinitely, and the only true remedy is out-of-band communication to the
colleges or the patient base that the key was lost. This is a property of asymmetric
cryptography, not a gap in the design, and the owner's risk register should carry it.

### 4.4 The mitigations that help with compromise

- **Short grant TTLs** bound the window (§5.4 of `protocolo.md`): 24 h default,
  minutes for sensitive capabilities.
- **Registry snapshot versions** are the *only* lever that works without any peer
  cooperating. Every credential carries `vigenteHasta` and `versionRegistro`, so a licence
  that stops being valid stops validating even if every peer that knew the node stays
  silent.
- **Announced key rotation is auditable.** Because `nodoId` derives from the **KEM** key,
  a rotation always produces a new `nodoId` (`identityFromSecret`/`conKem` document this
  explicitly), so a compromised key that rotates is visibly a different node and must
  re-earn credentials rather than inherit them.

---

## DECISIONES QUE NECESITAN DEL DUEÑO

**H. Confianza y reputación**

**H. Confianza y reputación**

- **H.1** — Umbral `K_AVAL` (karma mínimo para **emitir** `Aval`). Si es demasiado bajo,
  los recién llegados se autoavalúan en bucle; si es demasiado alto, el cold-start es
  insoluble sin una cohorte fundador. Requiere un número explícito.
- **H.2** — ¿Existe una **cohorte fundador** avalada de antemano por el dueño? Es lo único
  que resuelve el cold-start de los umbrales, y es una decisión de negocio, no de
  protocolo.
- **H.3** — ¿Las reseñas de **pacientes** tienen algún efecto, aunque sea de presentación?
  Recomendación: ninguno sobre el estado de credencial. Pero si el dueño quiere que
  "muchas malas reseñas" bajen la *visibilidad*, hay que decidir explícitamente quién
  decide eso, porque es el sesgo más de tipo "ratings-as-a-service" de todo el sistema.
- **H.4** — ¿Se permiten reseñas **anónimas** de pacientes a cambio de una mayor cobertura
  de moderación? Diseñado: no (anónimo = imposible de sancionar = bomba). Si el dueño lo
  quiere, hace falta una capa de moderación con identidadrevealed-on-demand, y eso es un
  producto distinto.

**I. Salida, datos y riesgo residual**

- **I.1** — ¿Se implementa la **declaración de salida firmada** (§4.2) en v1, o la salida
  es simplemente "el nodo dejó de hablar"? La primera da una baja atribuible y limpia; la
  segunda es más barata y deja `Aval`s activos de un nodo fantasma hasta que caducan.
- **I.2** — ¿Los registros replicados de un nodo que se va (credencial, `Aval`s, historial
  de karma) se pueden borrar a petición, o se **conservan**? El diseño dice conservar
  (borrar sería permitir auto-borrar pruebas). Esto choca de frente con el derecho de
  supresión y **necesita criterio legal, no técnico**.
- **I.3** — ¿Se acepta en el registro de riesgos que un **laptop clínico robado** deja un
  historial firmado irrevocable (§4.3), cuya única salida es avisar a los colegios o a los
  pacientes fuera de banda? Si no se acepta, la alternativa real es exigir hardware con
  clave protected en un almacén seguro, que es una decisión de producto mayor.
- **I.4** — ¿Cuál es el **plazo de caducidad** por defecto de `Aval` (`alcance: 'anual'`
  propuesto) y quién lo refresca: el propio avalador, o un proceso automático? Sin un
  propietario claro, la caducidad no ocurre y la red se estanca.
- **I.5** — ¿El dueño acepta públicamente el residual de **colusión** (§3.3)? Un clique de
  diez médicos que se avalan mutuamente satisface todas las reglas. El diseño no afirma
  resolverlo; la única mitigación real es el ancla `anclada_autoridad` (firma del colegio).

**J. Reseñas y moderación**

- **J.1** — ¿Quién **modera** las reseñas públicas y con qué criterio? La mitigación 4 de
  §3.1 (colapsar las reseñas de nodos de poco standing) es una censura invisible si no se
  rotula como tal en la UI.
- **J.2** — ¿Las reseñas se pueden **reportar**, y qué pasa con las reportadas: se ocultan de
  inmediato o solo se investigan? Ocultar de inmediato favorece a la víctima y abre la
  puerta a silenciarCritics.
- **J.3** — ¿Existe un **canal de emergencia** fuera de la red (alerta al colegio o al
  Ministerio) cuando una reseña parece acusar un delito real y no opinar sobre la atención?
  Una red pública de reseñas de médicos sin salida institucional es un riesgo regulatorio
  real en Colombia y en la UE.
- **J.4** — ¿Se exige que las reseñas declaren el **tipo de interacción** que las sostiene
  (consulta presencial, telemedicina, simple opinión) sin revelar datos del paciente? Es un
  equilibrio entre utilidad y reidentificación.