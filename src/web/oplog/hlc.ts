// Hybrid logical clock. Wire format: 15-digit wall ms + "-" + 5-digit counter, so string order == causal order.

const WALL = 15;
const CTR = 5;
const CTR_MAX = 99_999;
const RE = /^\d{15}-\d{5}$/;

export interface HlcParts {
	wall: number;
	counter: number;
}

export const formatHlc = (wall: number, counter: number): string =>
	`${String(wall).padStart(WALL, "0")}-${String(counter).padStart(CTR, "0")}`;

export function parseHlc(s: unknown): HlcParts | null {
	if (typeof s !== "string" || !RE.test(s)) return null;
	return { wall: Number(s.slice(0, WALL)), counter: Number(s.slice(WALL + 1)) };
}

export const isHlc = (s: unknown): s is string =>
	typeof s === "string" && RE.test(s);

/** Wall-clock ms part (what grant notBefore/expiresAt are compared with). */
export const hlcWall = (s: string): number => Number(s.slice(0, WALL));

export const compareHlc = (a: string, b: string): number =>
	a < b ? -1 : a > b ? 1 : 0;

export interface HlcClock {
	/** next timestamp, strictly greater than every timestamp issued or observed */
	now(): string;
	/** merge a timestamp seen from another device (call only for accepted, non-future ops) */
	observe(remote: string): void;
	last(): string;
}

export function createHlc(
	physical: () => number = Date.now,
	start?: string,
): HlcClock {
	let last = start && isHlc(start) ? start : formatHlc(0, 0);
	return {
		now() {
			const p = parseHlc(last) as HlcParts;
			const pt = Math.floor(physical());
			let next: HlcParts;
			if (pt > p.wall) next = { wall: pt, counter: 0 };
			else if (p.counter < CTR_MAX)
				next = { wall: p.wall, counter: p.counter + 1 };
			else next = { wall: p.wall + 1, counter: 0 };
			last = formatHlc(next.wall, next.counter);
			return last;
		},
		observe(remote) {
			if (isHlc(remote) && remote > last) last = remote;
		},
		last: () => last,
	};
}
