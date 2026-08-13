import { createContext, useContext } from "react";
import type { EdgeMesh } from "@iberi22/edge-mesh";

export const EdgeMeshContext = createContext<EdgeMesh | null>(null);

/**
 * Hook to access the current EdgeMesh instance from the React context.
 */
export function useEdgeMesh(): EdgeMesh {
	const context = useContext(EdgeMeshContext);
	if (!context) {
		throw new Error("useEdgeMesh must be used within an EdgeMeshProvider");
	}
	return context;
}
