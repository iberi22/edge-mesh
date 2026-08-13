import { describe, expect, it } from "vitest";
import {
	namespacesAreIsolated,
	parseSwalNamespace,
	swalNamespace,
} from "../../src/namespaces/index.js";

describe("swal namespace isolation (DL-F1-02)", () => {
	it("formats swal/{app}/{instance}", () => {
		expect(swalNamespace("worldexams", "inst-a")).toBe("swal/worldexams/inst-a");
	});

	it("keeps two instances isolated", () => {
		const a = swalNamespace("app", "i1");
		const b = swalNamespace("app", "i2");
		expect(a).not.toBe(b);
		expect(namespacesAreIsolated(a, b)).toBe(true);
		expect(namespacesAreIsolated(a, a)).toBe(false);
	});

	it("parses valid namespaces", () => {
		expect(parseSwalNamespace("swal/x/y")).toEqual({
			appId: "x",
			instanceId: "y",
		});
		expect(parseSwalNamespace("global")).toBeNull();
	});
});
