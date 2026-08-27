/**
 * Conflict resolver for concurrent backlog updates.
 * Implements last-writer-wins with vector clocks.
 */

export interface VectorClock {
	[nodeId: string]: number;
}

export interface ConflictEntry {
	key: string;
	localValue: unknown;
	remoteValue: unknown;
	localClock: VectorClock;
	remoteClock: VectorClock;
	timestamp: number;
}

/**
 * Compare two vector clocks.
 * Returns: -1 if a < b, 0 if concurrent, 1 if a > b
 */
export function compareClocks(a: VectorClock, b: VectorClock): number {
	let aGreater = false;
	let bGreater = false;

	const allNodes = new Set([...Object.keys(a), ...Object.keys(b)]);
	for (const node of allNodes) {
		const aVal = a[node] ?? 0;
		const bVal = b[node] ?? 0;
		if (aVal > bVal) aGreater = true;
		if (bVal > aVal) bGreater = true;
	}

	if (aGreater && !bGreater) return 1;
	if (bGreater && !aGreater) return -1;
	return 0; // concurrent
}

/**
 * Resolve conflict using last-writer-wins.
 * If concurrent, use timestamp as tiebreaker.
 */
export function resolveConflict(
	local: unknown,
	remote: unknown,
	localClock: VectorClock,
	remoteClock: VectorClock,
	localTimestamp: number,
	remoteTimestamp: number,
): { winner: "local" | "remote"; reason: string } {
	const cmp = compareClocks(localClock, remoteClock);

	if (cmp === 1) {
		return { winner: "local", reason: "local clock dominates" };
	}
	if (cmp === -1) {
		return { winner: "remote", reason: "remote clock dominates" };
	}

	// Concurrent — use timestamp
	if (localTimestamp >= remoteTimestamp) {
		return { winner: "local", reason: "concurrent, local newer" };
	}
	return { winner: "remote", reason: "concurrent, remote newer" };
}

/**
 * Increment vector clock for a node.
 */
export function incrementClock(
	clock: VectorClock,
	nodeId: string,
): VectorClock {
	return {
		...clock,
		[nodeId]: (clock[nodeId] ?? 0) + 1,
	};
}
