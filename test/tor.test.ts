import { afterEach, beforeEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import {
	DEFAULT_TOR_CONFIG,
	generateTorrc,
	getTorDataDir,
	TorOnionTransport,
} from "../src/transport/tor.js";
import type { NodoId } from "../src/types/index.js";

describe("Tor Onion v3 Transport", () => {
	const testDir = path.join(os.tmpdir(), `edge-mesh-tor-test-${Date.now()}`);

	beforeEach(() => {
		fs.mkdirSync(testDir, { recursive: true });
	});

	afterEach(() => {
		try {
			fs.rmSync(testDir, { recursive: true, force: true });
		} catch {}
	});

	it("has Tor disabled by default (opt-in)", () => {
		expect(DEFAULT_TOR_CONFIG.enabled).toBe(false);

		const transport = new TorOnionTransport("nodo-tor-1" as NodoId);
		expect(transport.config.enabled).toBe(false);
	});

	it("generates correct torrc with HiddenService v3 configuration", () => {
		const config = {
			enabled: true,
			localPort: 9000,
			socksPort: 9050,
			controlPort: 9051,
		};

		const torrc = generateTorrc(config, testDir);
		expect(torrc).toContain(`DataDirectory ${testDir}`);
		expect(torrc).toContain(`HiddenServiceDir ${path.join(testDir, "onion")}`);
		expect(torrc).toContain("HiddenServicePort 9000 127.0.0.1:9000");
		expect(torrc).toContain("HiddenServiceVersion 3");
	});

	it("reads persistent .onion address from hostname file", () => {
		const hiddenServiceDir = path.join(testDir, "onion");
		fs.mkdirSync(hiddenServiceDir, { recursive: true });
		const mockOnion = "expyuzl53g3v5a5e3xzgq4tkmhfvz347n5i4h2a3v7q9k2l5j4d3z2yd.onion";
		fs.writeFileSync(path.join(hiddenServiceDir, "hostname"), mockOnion);

		const transport = new TorOnionTransport("nodo-tor-2" as NodoId, {
			enabled: true,
			dataDir: testDir,
		});

		const address = transport.getOnionAddress();
		expect(address).toBe(mockOnion);
	});

	it("returns null when start is called with Tor disabled", async () => {
		const transport = new TorOnionTransport("nodo-tor-3" as NodoId, {
			enabled: false,
		});

		const res = await transport.start();
		expect(res).toBeNull();
		expect(transport.estaConectado()).toBe(false);
	});
});
