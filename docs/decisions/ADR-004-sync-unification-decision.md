# ADR-004: Archtectural Separation and Coexistence of Yjs CRDT and OpLog SyncEngine

## Status
Accepted (2026-07-17)

## Context
The codebase implements two distinct replication/synchronization frameworks:
1. **Yjs CRDT Path (`YjsAdapter`)**: Replicates state using Conflict-Free Replicated Data Types. State is exchanged as binary updates (`Uint8Array`) based on state vectors, ensuring mathematically guaranteed convergence without central coordination.
2. **OpLog SyncEngine (`SyncEngine`)**: Replicates state as a chronological ledger of discrete semantic actions/transactions (`Operacion`). It tracks logical transitions, relying on monotonically increasing sequence clocks per node to detect history gaps and reconcile conflicts via sequential comparison.

`features.json` (F-003) notes that the `SyncEngine` of OpLog is not unified with the Yjs path. This ADR documents our decision regarding their integration.

## Decision
We decide to keep the underlying synchronization paths for **Yjs CRDT** and **OpLog SyncEngine** physically and architecturally separate, while unifying them logically under the `EdgeMesh` coordinator class.

Instead of merging them into a single synchronization engine (which would degrade the unique performance and design guarantees of both), they will coexist as parallel capabilities exposed by `EdgeMesh`:
* **CRDT Sync (Yjs)** is used for document-level states (e.g. distributed store menus, profiles, or shared canvases) where idempotent state-vector-based convergence is paramount.
* **OpLog Sync** is used for logical ledgers, audit logs, and sequential state-transition logs where historical order, structural operations, and custom event logging are needed.

## Consequences & Rationale

1. **Incompatible Reconcile Paradigms**:
   * Yjs uses state vectors for diff calculations. Applying a remote update is associative, commutative, and idempotent. No custom conflict resolution callback or sequential ordering is required on the network layer.
   * OpLog relies on strict vector clocks, sequential ranges, and logical comparisons. Merging logs might result in concurrent sequence conflicts, requiring a distinct logic path to determine which actions win or how they are appended.

2. **Performance Optimization**:
   * Conflating Yjs into an OpLog path would force binary-encoded document states into JSON transaction records, inducing heavy encoding/decoding overhead and breaking Yjs's built-in optimized update streaming.
   * Forcing OpLog logs into Yjs maps would obscure individual operation metadata (such as original transaction timestamps, specific authors, and precise transition kinds) under Yjs's internal CRDT transaction blocks.

3. **Unified Developer Interface**:
   * `EdgeMesh` exposes both capabilities cleanly. Developers can retrieve the Yjs adapter via `yjsAdapter` or initiate/manage logical log syncs via `obtenerSyncEngine(docId)`.
   * Real-time network events, presence online/offline states, and authorized namespaces are shared by both protocols, ensuring a single transport layer handles both modes.
