# Estrategia de Distribución de Workspace y Política SSOT

Este documento define la arquitectura y la estrategia de distribución del proyecto **Edge Mesh** como un monorepo/workspace único, detallando la coexistencia del Core y los Consumidores (como Shelf y la suite Maloca) y estableciendo la política de **Single Source of Truth (SSOT)** resultante.

---

## 1. Contexto de la Decisión (2026-07-29)

Históricamente, existían múltiples copias de código de `edge-mesh` sincronizadas manualmente entre diferentes repositorios locales y de producción:
1. `E:\proyectosSWAL\edge-mesh` — Repositorio independiente (standalone) utilizado para desarrollo aislado.
2. `E:\proyectosSWAL\shelf\packages\edge-mesh` — Paquete integrado dentro del monorepo de la aplicación Shelf.

Esta duplicidad generaba riesgos severos de sincronización y de inconsistencia en los binarios compilados y dependencias (ej. enlaces simbólicos rotos, ediciones accidentales directamente en artefactos `/dist` en lugar de `/src`).

### Decisión del Propietario
Para mitigar estos riesgos de forma definitiva, se adopta la **distribución como un workspace/monorepo único**. En este nuevo paradigma, el core de la red mesh y sus consumidores conviven dentro de un mismo espacio de trabajo unificado y gestionado por herramientas modernas de monorreferencia (como npm/pnpm/yarn workspaces).

---

## 2. Arquitectura del Workspace / Monorepo Único

El monorepo está estructurado para segmentar de forma limpia el motor principal (Core), los adaptadores y las aplicaciones consumidoras.

```
edge-mesh-workspace/
├── package.json                   # Configuración del Monorepo (npm workspaces)
├── docs/                          # Documentación del sistema y decisiones de diseño
├── packages/
│   ├── edge-mesh/                 # @iberi22/edge-mesh (Paquete Core / SSOT)
│   │   ├── src/                   # Código fuente de red mesh, PQC identity, WebRTC, Yjs
│   │   ├── tests/                 # Pruebas unitarias y de integración del Core
│   │   └── package.json           # Declaración y dependencias del Core
│   │
│   ├── maloca-kernel/             # @edge-mesh/maloca (Gestión descentralizada y gateways)
│   │   ├── src/                   # Karma, profiles, metadata y plugin registry
│   │   └── package.json           # Depende directamente de "@iberi22/edge-mesh"
│   │
│   ├── adapters/                  # Adaptadores especializados de industria
│   │   ├── xavier/                # @edge-mesh/adapters-xavier (AI orchestration)
│   │   ├── salud/                 # @edge-mesh/adapters-salud (OrionHealth)
│   │   └── veeduria/              # @edge-mesh/adapters-veeduria (VeedurIA)
│   │
│   └── shelf-app/                 # Aplicación de consumo final (Shelf)
│       ├── src/                   # Capa de presentación y reglas de negocio SWAL
│       └── package.json           # Depende de "@iberi22/edge-mesh" y "@edge-mesh/maloca"
```

---

## 3. Coexistencia de Core y Consumidores

### Aislamiento de Capas
1. **El Core (`@iberi22/edge-mesh`)** se mantiene 100% agnóstico a las reglas de negocio específicas de las aplicaciones. Es responsable únicamente del transporte WebRTC/PeerJS, autenticación de identidad post-cuántica (ML-DSA-65), control de namespaces de red y la orquestación/guards de sincronización de documentos Yjs.
2. **Los Adaptadores (`@edge-mesh/adapters-*`)** consumen la API pública del Core para conectar sistemas externos (ej. blockchain Polygon en Evidentia, APIs de LLM en Xavier, registros médicos en Salud) sin contaminar los archivos fuente del core de red.
3. **Las Aplicaciones de Usuario (`Shelf`, `Maloca Gateway`)** consumen tanto el core como los adaptadores a nivel de cliente para brindar las interfaces de usuario finales y servicios WebSockets.

---

## 4. Política Single Source of Truth (SSOT)

Para garantizar la integridad y coherencia absoluta del código, se establecen las siguientes reglas operativas obligatorias de SSOT:

### Regla #1: Prohibido Editar en `node_modules` o Carpeta `dist/`
Bajo ninguna circunstancia se debe editar el código compilado dentro de directorios `dist/` ni directamente dentro de las dependencias en `node_modules`. Todo cambio debe originarse en la carpeta `src/` correspondiente de su paquete fuente dentro del workspace.

### Regla #2: Resolución Automática de Enlaces de Workspace
Las referencias cruzadas se resuelven mediante el mapeo nativo del workspace. Al utilizar `pnpm install` o `npm install` en la raíz del monorepo, el gestor de paquetes creará automáticamente enlaces simbólicos (symlinks) dinámicos de desarrollo:
- `packages/shelf-app/node_modules/@iberi22/edge-mesh` apuntará en tiempo real a `packages/edge-mesh`.
- Cualquier cambio de código guardado en los archivos `.ts` del Core es inmediatamente visible para los consumidores sin necesidad de pre-publicar el paquete en registros remotos (NPM/GitHub Packages).

### Regla #3: Ciclo de Compilación Integrado
Para construir el sistema completo:
1. Las modificaciones al Core se compilan corriendo `npm run build` en el paquete core (o de forma automática con tsc watch en modo dev).
2. Los consumidores importan las definiciones TypeScript del Core directamente desde el output de types del core, garantizando un tipado estático consistente al 100%.

### Regla #4: Proceso de Publicación Único
El proceso de publicación en registros remotos (ej. GitHub Packages `@iberi22/edge-mesh`) está unificado bajo la automatización de CI/CD (`.github/workflows/ci.yml`) y se dispara exclusivamente tras fusionar cambios validados y verificados a la rama `main`.
