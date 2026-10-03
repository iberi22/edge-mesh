// @iberi22/edge-mesh/web/oplog — signed, hash-chained per-device operation logs gated by web/trust.

export type { HlcClock, HlcParts } from "./hlc.js";
export {
	compareHlc,
	createHlc,
	formatHlc,
	hlcWall,
	isHlc,
	parseHlc,
} from "./hlc.js";
export type { OpLogEvents, OpLogOptions, OpVerdict } from "./log.js";
export { compareOps, OpLog, OpLogError, openOpLog } from "./log.js";
export type { OpStore, QuarantineStore } from "./store.js";
export { MemoryOpStore, MemoryQuarantineStore } from "./store.js";
export type { OpLogChannel, OpLogSync, ServeOptions } from "./sync.js";
export {
	attachOpLogSync,
	decodeMessage,
	encodeMessage,
	haveMessage,
	serve,
	wantFor,
} from "./sync.js";
export type {
	Checkpoint,
	CheckpointHook,
	HaveMsg,
	IngestResult,
	IngestStatus,
	Op,
	OpBody,
	OpInput,
	OpLogMessage,
	OpRange,
	OpsMsg,
	PendingReason,
	QuarantineEntry,
	QuarantineReason,
	StoredOp,
	WantMsg,
} from "./types.js";
