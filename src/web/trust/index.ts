// @iberi22/edge-mesh/web/trust — signed capabilities (grants/revocations) chained to a root key.
export {
	canonicalBytes,
	canonicalJson,
	contentId,
	sha256B64u,
} from "./canonical.js";
export type { GrantInput, IssueContext, RevocationInput } from "./docs.js";
export {
	bodyOf,
	checkGrantShape,
	checkIntegrity,
	checkRevocationShape,
	issueGrant,
	issueRevocation,
	rolePreset,
	verifyDocSignature,
} from "./docs.js";
export type { SigAlg, Signer } from "./keys.js";
export {
	createSigner,
	generateSigner,
	isPublicKey,
	isSignature,
	keyFingerprint,
	PUBLIC_KEY_BYTES,
	SIG_ALG,
	SIGNATURE_BYTES,
	signBytes,
	signCanonical,
	verifyBytes,
	verifyCanonical,
} from "./keys.js";
export type { Anchor, TrustStoreOptions } from "./store.js";
export { createTrustStore, TrustStore } from "./store.js";
export type {
	AddResult,
	AddStatus,
	At,
	Decision,
	DenyReason,
	DeviceRef,
	Grant,
	GrantBody,
	Level,
	Permissions,
	Revocation,
	RevocationBody,
	RolePreset,
	TrustDoc,
	TrustSchema,
} from "./types.js";
export { isLevel, LEVELS, levelRank } from "./types.js";
