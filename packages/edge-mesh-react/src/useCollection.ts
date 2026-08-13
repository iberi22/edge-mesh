import { useState, useEffect } from "react";
import { useEdgeMesh } from "./useEdgeMesh";
import * as Y from "yjs";

export interface UseCollectionOptions {
	type?: "map" | "array";
}

/**
 * Hook to subscribe to a shared Yjs collection (Map or Array) and access its state in React.
 * Provides helper methods for common CRUD mutations.
 */
export function useCollection<T = any>(
	name: string,
	options: UseCollectionOptions = {},
) {
	const edgeMesh = useEdgeMesh();
	const type = options.type ?? "map";

	// Get collection instance
	const collection =
		type === "map"
			? edgeMesh.yjsAdapter.getMap(name)
			: edgeMesh.yjsAdapter.getArray(name);

	const getSnapshot = () => {
		if (type === "map") {
			const map = collection as Y.Map<any>;
			const items: any[] = [];
			map.forEach((value, key) => {
				if (value && typeof value === "object") {
					items.push({ id: key, ...value });
				} else {
					items.push({ key, value });
				}
			});
			return items as T[];
		} else {
			const arr = collection as Y.Array<any>;
			return arr.toArray() as T[];
		}
	};

	const [state, setState] = useState<T[]>(getSnapshot);

	useEffect(() => {
		// Initial sync
		setState(getSnapshot());

		const handler = () => {
			setState(getSnapshot());
		};

		collection.observe(handler);
		return () => {
			collection.unobserve(handler);
		};
	}, [collection, type]);

	// Mutating helpers
	const add = (item: any) => {
		if (type === "array") {
			(collection as Y.Array<any>).push([item]);
		} else {
			const id =
				item.id || item.key || Math.random().toString(36).substring(2, 11);
			(collection as Y.Map<any>).set(id, item);
		}
	};

	const remove = (idOrIndex: any) => {
		if (type === "array") {
			if (typeof idOrIndex === "number") {
				(collection as Y.Array<any>).delete(idOrIndex, 1);
			}
		} else {
			(collection as Y.Map<any>).delete(idOrIndex);
		}
	};

	const update = (key: string, value: any) => {
		if (type === "map") {
			(collection as Y.Map<any>).set(key, value);
		}
	};

	const set = (key: string, value: any) => {
		if (type === "map") {
			(collection as Y.Map<any>).set(key, value);
		}
	};

	const get = (key: string) => {
		if (type === "map") {
			return (collection as Y.Map<any>).get(key);
		}
		return undefined;
	};

	return [
		state,
		{
			collection,
			add,
			remove,
			update,
			set,
			get,
		},
	] as const;
}
