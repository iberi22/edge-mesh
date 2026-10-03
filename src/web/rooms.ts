import { b64uEncode, bs, concat, utf8 } from "./util.js";

export type TopicScope = "data" | "presence" | "inbox" | "exchange" | "vault";

/** Topic taxonomy: `{appId}/{scope}/{subject}` */
export function topic(app: string, scope: TopicScope | (string & {}), subject: string): string {
	for (const [k, v] of [["app", app], ["scope", scope], ["subject", subject]] as const) {
		if (!v || v.includes("/") || v.includes("|")) throw new Error(`invalid topic ${k}: "${v}"`);
	}
	return `${app}/${scope}/${subject}`;
}

/** Compatibility with the existing `swal/{app}/{instance}` namespaces. */
export function legacyNamespace(app: string, instance: string): string {
	return `swal/${app}/${instance}`;
}

export async function hmac(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
	const k = await crypto.subtle.importKey("raw", bs(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	return new Uint8Array(await crypto.subtle.sign("HMAC", k, bs(data)));
}

/**
 * rid = base64url(HMAC-SHA256(meshKey, "swal-room/v1|appId|topic[|epoch][|i:instance]"))[0..22]
 * epoch 0 keeps the MESH.md formula; epoch>0 appends "|epoch" (rotation). `instance` (the mesh's own
 * namespace, e.g. the fingerprint of its owner or a restaurant id) keeps two instances of the same app apart
 * even if they end up with the same mesh key and topic.
 */
export async function deriveRoomId(
	meshKey: Uint8Array,
	appId: string,
	topicName: string,
	epoch = 0,
	instance?: string,
): Promise<string> {
	if (instance !== undefined && (!instance || instance.includes("|") || instance.includes("/"))) {
		throw new Error(`invalid instance "${instance}"`);
	}
	const label = `swal-room/v1|${appId}|${topicName}` + (epoch > 0 ? `|${epoch}` : "") + (instance ? `|i:${instance}` : "");
	return b64uEncode(await hmac(meshKey, utf8(label))).slice(0, 22);
}

/** Short stable id of a public key: base64url(SHA-256(key))[0..22] (132 bits). */
export async function fingerprint(publicKey: Uint8Array): Promise<string> {
	return b64uEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", bs(publicKey)))).slice(0, 22);
}

/** Namespace of one mesh instance: `{appId}/{instance}`; channels live under `{appId}/{instance}/{kind}`. */
export function meshNamespace(appId: string, instance: string): string {
	return `${appId}/${instance}`;
}

/** Pairing room: rid_pair = "p_" + H(pairSecret)[0..20] (domain separated; the `p_` prefix selects the signaling server's pairing-room admission). */
export async function derivePairRoomId(pairSecret: Uint8Array): Promise<string> {
	const h = await crypto.subtle.digest("SHA-256", bs(concat(utf8("swal-pair-room/v1|"), pairSecret)));
	return "p_" + b64uEncode(new Uint8Array(h)).slice(0, 20);
}
