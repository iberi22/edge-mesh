# Tracker de Issues — EPIC #22: Integración de EdgeMesh & Maloca

Este documento reconcilia y realiza el seguimiento oficial de los 15 issues pertenecientes a la **EPIC #22: Integración Core & Adaptadores Maloca**.

Siguiendo la decisión del propietario del proyecto (2026-07-29) de distribuir el paquete como un monorepo/workspace único y desacoplar los adaptadores específicos de Maloca del núcleo (Core), los estados de los issues han sido reconciliados y actualizados a continuación.

---

## Resumen de Estado del Tracker

* **Total de Issues:** 15
* **Cerrados / Resueltos (Fixed):** 9
* **Transicionados / Re-etiquetados (Workspace Package):** 6

---

## Tabla de Reconciliación de Issues

| ID de Issue | Título del Issue | Módulo / Ruta | Estado Anterior | Estado Actual | Resolución / Notas |
|-------------|------------------|---------------|-----------------|---------------|--------------------|
| **#22-01** | Implementación del Ciclo de Vida del Nodo P2P | `src/core/node.ts` | Abierto | **Cerrado - Fixed** | Implementado completamente con transiciones de estado robustas y testeadas en `tests/core/node.test.ts`. |
| **#22-02** | Integración del Canal de Transporte WebRTC PeerJS | `src/transport/peerjs.ts` | Abierto | **Cerrado - Fixed** | Capa de transporte funcional integrada y probada con reconexión automática resiliente. |
| **#22-03** | Sincronización de CRDTs vía Yjs Adapter | `src/edge-mesh.ts` | Abierto | **Cerrado - Fixed** | Sincronización de Y.Doc integrada con guards de mutación y self-healing quirúrgico. |
| **#22-04** | Criptografía de Identidad Post-Cuántica ML-DSA-65 | `src/identity/index.ts` | Abierto | **Cerrado - Fixed** | Identidad generada a partir de semilla de 32 bytes con firma/verificación deterministicas. |
| **#22-05** | Canales de Chat Colaborativos P2P | `src/chat/index.ts` | Abierto | **Cerrado - Fixed** | Mensajería con buffer de almacenamiento offline (`PersistentOfflineQueue`) y sincronización Yjs. |
| **#22-06** | Sistema de Salones Virtuales y Exámenes | `src/salones/manager.ts` | Abierto | **Cerrado - Fixed** | Orquestación de estados y participantes de salones completamente funcional. |
| **#22-07** | Protocolo de Gossip Escalable para Mesh | `src/mesh/index.ts` | Abierto | **Cerrado - Fixed** | Algoritmo Gossip con fan-out configurable probado para más de 50 peers concurrentes. |
| **#22-08** | Control de Acceso por Namespace de Capacidades | `src/authz/index.ts` | Abierto | **Cerrado - Fixed** | Almacenamiento y persistencia IndexedDB de grants, roles y capabilities. |
| **#22-09** | Persistencia Dual IndexedDB & In-Memory | `src/storage/index.ts` | Abierto | **Cerrado - Fixed** | Motor `StorageManager` robusto con IndexedDB y fallback seguro a InMemory para testing. |
| **#22-10** | Gateway de Maloca (REST, WS & Dashboard) | `src/maloca/gateway/` | Abierto | **Transicionado** | Re-etiquetado para migración al paquete workspace `@edge-mesh/maloca` (ADR-004). |
| **#22-11** | Puente Ethereum/Polygon Bridge para Evidentia | `src/maloca/polygon-bridge.ts` | Abierto | **Transicionado** | Re-etiquetado para migración al paquete workspace `@edge-mesh/evidentia`. |
| **#22-12** | Adaptador AI Xavier (Orquestación & Code-Graph) | `src/adapters/maloca-xavier/` | Abierto | **Transicionado** | Re-etiquetado para migración al paquete workspace `@edge-mesh/adapters-xavier`. |
| **#22-13** | Adaptador Licitaciones Públicas VeedurIA | `src/adapters/maloca-veeduria/` | Abierto | **Transicionado** | Re-etiquetado para migración al paquete workspace `@edge-mesh/adapters-veeduria`. |
| **#22-14** | Sincronización Post-Partición Catch-Up por State Vector | `src/edge-mesh.ts` | Abierto | **Cerrado - Fixed** | Sincronización automática incremental tras reconexión usando state vectors. |
| **#22-15** | Adaptador Salud OrionHealth (Citas Distribuidas) | `src/adapters/maloca-salud/` | Abierto | **Transicionado** | Re-etiquetado para migración al paquete workspace `@edge-mesh/adapters-salud`. |

---

## Política de Transición a Workspace

Para aquellos adaptadores etiquetados como **Transicionado**, la implementación de código ya ha sido validada y aislada dentro de sus respectivos directorios bajo la futura estructura del monorepo único. Los issues se cierran en este tracker del repositorio core de `EdgeMesh` y se abrirán correspondientemente en los trackers de sus nuevos paquetes independientes dentro del workspace unificado.
