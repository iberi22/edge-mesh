import {
	type OpLog,
	type OpLogOptions,
	openOpLog,
} from "../../src/web/oplog/index.js";
import {
	createTrustStore,
	type Grant,
	type GrantInput,
	generateSigner,
	issueGrant,
	issueRevocation,
	type RevocationInput,
	rolePreset,
	type Signer,
	type TrustSchema,
	type TrustStore,
} from "../../src/web/trust/index.js";

export const INST = "local-test";
export const T0 = 1_760_000_000_000;

/** Example app schema (Fize-like, test only: the core never hard-codes modules). */
export const SCHEMA: TrustSchema = {
	modules: ["carta", "pedidos", "cocina", "inventario", "personal"],
	roles: {
		admin: {
			permissions: {
				carta: "administrar",
				pedidos: "administrar",
				cocina: "administrar",
				inventario: "administrar",
				personal: "ver",
			},
			delegate: 1,
		},
		owner: {
			permissions: {
				carta: "administrar",
				pedidos: "administrar",
				cocina: "administrar",
				inventario: "administrar",
				personal: "administrar",
			},
			delegate: 1,
		},
		mesero: {
			permissions: { carta: "ver", pedidos: "editar", cocina: "editar" },
		},
		cocina: {
			permissions: {
				carta: "ver",
				pedidos: "ver",
				cocina: "editar",
				inventario: "ver",
			},
		},
	},
	actionLevel: (module, action) => {
		if (action.startsWith("view")) return "ver";
		if (action === "delete" || action === "restore" || action === "void")
			return "administrar";
		return module === "personal" ? "administrar" : "editar";
	},
};

export interface Clock {
	t: number;
	now: () => number;
}
export const clock = (t = T0): Clock => {
	const c: Clock = { t, now: () => c.t };
	return c;
};

export interface World {
	root: Signer;
	owner: Signer;
	admin: Signer;
	waiter: Signer;
	cook: Signer;
	g: { owner: Grant; admin: Grant; waiter: Grant; cook: Grant };
	/** all valid grants in issue order */
	docs: Grant[];
	clk: Clock;
	trust(opts?: { maxDepth?: number; now?: () => number }): Promise<TrustStore>;
	log(
		signer: Signer | undefined,
		trust: TrustStore,
		opts?: Partial<OpLogOptions>,
	): Promise<OpLog>;
	grant(
		issuer: Signer,
		subject: Signer,
		input: Partial<GrantInput> & { role: string },
		parent?: Grant,
	): Promise<Grant>;
	revoke(
		issuer: Signer,
		input: RevocationInput,
		parent?: Grant,
	): ReturnType<typeof issueRevocation>;
}

/**
 * root (owner key) -> owner device [owner], admin device [admin]; admin -> cook [cocina]; root -> waiter [mesero].
 * So `cook` is a descendant of `admin` (cascade tests) and `waiter` is root-anchored.
 */
export async function world(): Promise<World> {
	const clk = clock();
	const [root, owner, admin, waiter, cook] = await Promise.all([
		generateSigner(),
		generateSigner(),
		generateSigner(),
		generateSigner(),
		generateSigner(),
	]);
	const grant: World["grant"] = (issuer, subject, input, parent) => {
		const preset = SCHEMA.roles?.[input.role]
			? rolePreset(SCHEMA, input.role)
			: { permissions: {}, delegate: 0 };
		return issueGrant(
			issuer,
			{
				...preset,
				notBefore: T0 - 1000,
				issuedAt: T0 - 1000,
				...input,
				subject: { jwk: subject.jwk },
			},
			{ inst: INST, parent, now: T0 - 1000 },
		);
	};
	const gOwner = await grant(root, owner, { role: "owner" });
	const gAdmin = await grant(root, admin, { role: "admin" });
	const gWaiter = await grant(root, waiter, { role: "mesero" });
	const gCook = await grant(admin, cook, { role: "cocina" }, gAdmin);
	const w: World = {
		root,
		owner,
		admin,
		waiter,
		cook,
		g: { owner: gOwner, admin: gAdmin, waiter: gWaiter, cook: gCook },
		docs: [gOwner, gAdmin, gWaiter, gCook],
		clk,
		trust: (o = {}) =>
			createTrustStore({
				inst: INST,
				root: root.jwk,
				schema: { ...SCHEMA, maxDepth: o.maxDepth ?? SCHEMA.maxDepth },
				now: o.now ?? clk.now,
			}),
		log: (signer, trust, opts = {}) =>
			openOpLog({ trust, signer, now: clk.now, ...opts }),
		grant,
		revoke: (issuer, input, parent) =>
			issueRevocation(issuer, input, { inst: INST, parent, now: clk.t }),
	};
	return w;
}

/** Deterministic PRNG (mulberry32) for shuffled-delivery tests. */
export function rng(seed: number) {
	let a = seed >>> 0;
	return () => {
		a = (a + 0x6d2b79f5) >>> 0;
		let t = a;
		t = Math.imul(t ^ (t >>> 15), t | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}

export function shuffle<T>(xs: readonly T[], rand: () => number): T[] {
	const a = [...xs];
	for (let i = a.length - 1; i > 0; i--) {
		const j = Math.floor(rand() * (i + 1));
		[a[i], a[j]] = [a[j] as T, a[i] as T];
	}
	return a;
}
