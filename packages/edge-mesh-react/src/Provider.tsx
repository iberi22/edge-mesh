import React, { type ReactNode } from "react";
import { EdgeMeshContext } from "./useEdgeMesh";
import type { EdgeMesh } from "@iberi22/edge-mesh";

export interface EdgeMeshProviderProps {
	edgeMesh: EdgeMesh;
	children: ReactNode;
}

/**
 * Provider component that makes the EdgeMesh instance available to any nested components that useuseEdgeMesh.
 */
export function EdgeMeshProvider({ edgeMesh, children }: EdgeMeshProviderProps) {
	return (
		<EdgeMeshContext.Provider value={edgeMesh}>
			{children}
		</EdgeMeshContext.Provider>
	);
}

export { EdgeMeshProvider as Provider };
