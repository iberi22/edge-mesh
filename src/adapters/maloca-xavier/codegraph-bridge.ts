import type { EdgeMesh } from "../../edge-mesh.js";
import type { NodoId } from "../../types/index.js";

export interface CodeGraphEntry {
  readonly id: string;
  readonly path: string;
  readonly metadata: Record<string, unknown>;
  readonly dependencies: readonly string[];
}

export class CodeGraphAdapter {
  private readonly edgeMesh: EdgeMesh;
  private readonly INDEX_MAP_NAME = "xavier:codegraph:index";
  private readonly CODEGRAPH_NAMESPACE = "xavier:codegraph";

  constructor(edgeMesh: EdgeMesh) {
    this.edgeMesh = edgeMesh;
  }

  /**
   * Realiza una búsqueda distribuida en el code-graph.
   * Por ahora, consulta el índice compartido en el Y.Map.
   */
  searchGraph(query: string): readonly CodeGraphEntry[] {
    const indexMap = this.edgeMesh.yjsAdapter.getMap(this.INDEX_MAP_NAME);
    const results: CodeGraphEntry[] = [];

    for (const entry of indexMap.values()) {
      const e = entry as CodeGraphEntry;
      if (e.id.includes(query) || e.path.includes(query)) {
        results.push(e);
      }
    }

    return results;
  }

  /**
   * Indexa un plugin en el code-graph compartido.
   */
  async indexPlugin(pluginPath: string, metadata: Record<string, unknown>, dependencies: readonly string[]): Promise<void> {
    // 1. Asegurar que estamos en el namespace
    const ns = this.edgeMesh.namespaces.obtenerEspacioPorNombre(this.CODEGRAPH_NAMESPACE);
    let nsId: string;
    if (!ns) {
      const newNs = this.edgeMesh.namespaces.crearEspacio(this.CODEGRAPH_NAMESPACE);
      nsId = newNs.id;
    } else {
      nsId = ns.id;
    }
    this.edgeMesh.namespaces.unirNodo(nsId, this.edgeMesh.config.nodoId);

    // 2. Actualizar el índice compartido
    const indexMap = this.edgeMesh.yjsAdapter.getMap(this.INDEX_MAP_NAME);
    const id = `plugin:${pluginPath}`;
    const entry: CodeGraphEntry = {
      id,
      path: pluginPath,
      metadata,
      dependencies,
    };
    indexMap.set(id, entry);
  }

  /**
   * Obtiene las dependencias de un módulo a través del mesh.
   */
  getDependencies(moduleId: string): readonly string[] {
    const indexMap = this.edgeMesh.yjsAdapter.getMap(this.INDEX_MAP_NAME);
    const entry = indexMap.get(moduleId) as CodeGraphEntry | undefined;
    return entry?.dependencies ?? [];
  }
}
