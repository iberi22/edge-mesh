# Auditorías de seguridad del núcleo

Este directorio guarda las auditorías de seguridad de `@iberi22/edge-mesh` (por ahora de la malla del navegador,
`src/web/`). Cada ronda tiene su propio documento con los hallazgos, su estado, el commit que los corrige y la
prueba de regresión que impide que vuelvan.

## Índice

| Ronda | Fecha | Alcance | Resultado | Documento |
|-------|-------|---------|-----------|-----------|
| 1 | 2026-10-03 | `web/provider`, emparejamiento, admisión, `web/trust`, `web/oplog`, `web/merge` | 6 bloqueantes, 7 a corregir y notas, todos corregidos | [2026-10-03-ronda-1.md](2026-10-03-ronda-1.md) |
| 2 | 2026-10-03 | Re-auditoría de `mesh/fix-audit` tras la ronda 1 | 3 bloqueantes, 5 a corregir y notas, todos corregidos | [2026-10-03-ronda-2.md](2026-10-03-ronda-2.md) |
| 3 | 2026-10-03 | Re-auditoría de `mesh/fix-audit` @ `4932376` | 3 bloqueantes y 3 a corregir; rediseño a re-clave solo por el dueño; todos corregidos | [2026-10-03-ronda-3.md](2026-10-03-ronda-3.md) |
| 4 | 2026-10-03 | Re-auditoría de `mesh/fix-audit` @ `18448f5`: migración post-cuántica y re-clave del dueño | Post-cuántica sin bloqueantes; 2 bloqueantes (R4-B1, R4-B2), 3 a corregir y notas; corregidos todos salvo las notas N1 y N4 (documentadas) | [2026-10-03-ronda-4.md](2026-10-03-ronda-4.md) |

## Método

1. **Revisión adversarial independiente.** Un auditor que no escribió el código busca ataques reales contra la
   rama: suplantación, escalada, denegación de servicio, pérdida de convergencia, fugas entre mallas. Clasifica
   cada hallazgo como **bloqueante**, **a corregir** (*should-fix*) o **nota**.
2. **Pruebas de prueba de concepto.** Cada hallazgo llega con una prueba ejecutable que **pasa mientras el ataque
   funciona**. Esas pruebas y sus registros se guardan junto a la ronda.
3. **Inversión en pruebas de regresión, primero en rojo.** Antes de corregir, la prueba del auditor se copia a
   `tests/web/audit-regressions*.test.ts` con la aserción invertida. Así falla mientras el ataque funciona (rojo) y
   pasa cuando deja de funcionar (verde). Cada documento de ronda nombra la prueba de cada hallazgo.
4. **Un commit por hallazgo** en la rama de corrección, con mensaje convencional en español y sin atribuciones.
   Nunca se hace commit con la suite en rojo: un script de puerta corre `tsc` y `vitest run tests/web` antes de
   cada commit.
5. **Verificación por ronda:** `npx tsc --noEmit` sale con 0; `npx biome check` en los archivos tocados no
   añade errores frente a la base; `npx vitest run tests/web` y `npm test`, cada uno al menos dos veces, en verde.
   Si hay fuzz de vivacidad, se ejecutan todas las semillas del auditor y otras tantas nuevas.
6. **Nunca se fusiona a `develop` sin una ronda limpia.** Una ronda es limpia cuando el auditor independiente no
   encuentra bloqueantes nuevos. Mientras queden bloqueantes, la rama sigue abierta y se audita otra vez.

## Pruebas de regresión

| Archivo | Contenido |
|---------|-----------|
| `tests/web/audit-regressions.test.ts` | Ronda 1, malla: P1–P6 (B1–B4, B6, S1), S5, S6 |
| `tests/web/audit-regressions-oplog.test.ts` | Ronda 1, `web/trust` y `web/oplog`: A1–A4 (B5, S2–S4), S7, notas; ronda 2 BL2; ronda 3 hallazgo 6 |
| `tests/web/audit-regressions-r2.test.ts` | Ronda 2: BL1, BL3, SF1–SF5 y notas (V1, V2, R6, …) |
| `tests/web/audit-regressions-r3.test.ts` | Ronda 3: rediseño, B1, B2, hallazgos 4 y 5, nota 9 |
| `tests/web/audit-fuzz-r3.test.ts` | Ronda 3: fuzz de vivacidad de 8 equipos (semillas 13 y 14 en la suite; `FUZZ_SEEDS=1,2,…` para más) |
| `tests/web/audit-regressions-pqc.test.ts` | Migración post-cuántica: identidades ML-DSA-65 (Q1–Q4) |
| `tests/web/audit-regressions-pqc-kex.test.ts` | Migración post-cuántica: intercambios híbridos, rotaciones firmadas y re-clave interrumpida (Q5–Q11) |
| `tests/web/audit-regressions-r4.test.ts` | Ronda 4: R4-B1, R4-B2, R4-S1–S3, notas N2, N3, N6 |
| `tests/web/trust-oplog-security.test.ts` | Batería de seguridad de `web/trust` / `web/oplog` anterior a las rondas |

## Cambios posteriores a la ronda 3 (auditados en la ronda 4)

La regla de `AGENTS.md` §2 (criptografía post-cuántica) se aplicó después de la ronda 3, y la ronda 4 cubrió
estos cambios. El detalle está en `docs/WEB-MESH-CRYPTO.md`, sección «Post-quantum cryptography».

| Commit | Cambio | Pruebas |
|--------|--------|---------|
| `076d697` | `web/trust` y `web/oplog`: concesiones, revocaciones y operaciones firmadas con ML-DSA-65; ES256 se rechaza | `trust.test.ts`, `trust-oplog-security.test.ts` |
| `cdf6364` | Identidad de equipo ML-DSA-65 (`deviceId = deviceIdOf(pub)`, 43 caracteres); toda firma de la malla verificada con ML-DSA-65; QR v4 sin firma y prueba de identidad del anfitrión dentro de la sesión SAS | Q1–Q4 |
| `c38507e` | Sesión de emparejamiento y envolturas de rotación híbridas ML-KEM-768 + ECDH P-256; llaves ML-KEM/P-256 inválidas rechazadas al recibirlas | Q5–Q8 |
| `0a720da` | El dueño firma cada rotación con ML-DSA-65; el grant lleva como mucho 16 revocaciones | Q9 |
| `ba4764b` | Una re-clave interrumpida por `destroy()` no escribe en la bóveda; el dueño retoma las re-claves pendientes al arrancar; el fuzz exige un estado estable 1,5 s | Q10/Q11, fuzz 96/96 |

Puntos que se pidió revisar al auditor de la ronda 4 (resultado en su documento):

- El QR ya no va firmado. La identidad del anfitrión se prueba dentro de la sesión autenticada por el SAS
  (`hostProof`). Hay que revisar que nada se acepte del QR antes de esa prueba.
- La combinación híbrida (`hybridSecret`) y qué se liga en la transcripción v5 y en la sal de las envolturas
  (`swal-rotate/v4`).
- El costo de ML-DSA (unos 7,6 ms por firma y 1,9 ms por verificación) como posible vector de denegación de
  servicio. Cada trama se verifica; solo se memorizan las cadenas de admisión, las revocaciones y las firmas de
  rotación.
- El tamaño de los registros (unos 3,4 KB por mensaje firmado) frente a los topes de 64 KiB por trama,
  32 KiB por operación y 256 KiB por mensaje de emparejamiento.
