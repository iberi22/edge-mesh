import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const PROBE = [
  "const m = await import('@iberi22/edge-mesh/web');",
  "const t = await import('@iberi22/edge-mesh/web/trust');",
  "console.log(Object.keys(m).length, Object.keys(t).length)",
].join(" ");
const OPTIONAL_PEERS = ["ethers", "peerjs", "ws"];

function run(file, args, cwd) {
  return execFileSync(file, args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    maxBuffer: 64 * 1024 * 1024,
  });
}

function parsePack(stdout) {
  try {
    const parsed = JSON.parse(stdout);
    return Array.isArray(parsed) ? parsed[0] : parsed;
  } catch {
    const start = stdout.indexOf("[");
    const end = stdout.lastIndexOf("]");
    if (start === -1 || end === -1) throw new Error("npm pack produced no JSON array");
    return JSON.parse(stdout.slice(start, end + 1))[0];
  }
}

function countInstalled(appDir) {
  const lockPath = path.join(appDir, "package-lock.json");
  if (fs.existsSync(lockPath)) {
    const lock = JSON.parse(fs.readFileSync(lockPath, "utf8"));
    const entries = Object.keys(lock.packages ?? {});
    return entries.filter((key) => key !== "").length;
  }
  const modules = path.join(appDir, "node_modules");
  if (!fs.existsSync(modules)) return 0;
  let total = 0;
  for (const entry of fs.readdirSync(modules, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.name.startsWith(".")) continue;
    if (entry.name.startsWith("@")) {
      const scope = path.join(modules, entry.name);
      total += fs
        .readdirSync(scope, { withFileTypes: true })
        .filter((e) => e.isDirectory() && !e.name.startsWith(".")).length;
    } else {
      total += 1;
    }
  }
  return total;
}

function assertOptionalPeersAbsent(appDir) {
  const modules = path.join(appDir, "node_modules");
  for (const name of OPTIONAL_PEERS) {
    const present = [name, path.join("node_modules", name)];
    const found = present.some((rel) => fs.existsSync(path.join(appDir, rel)));
    if (found) {
      process.stderr.write(
        `pack:smoke warning: optional peer "${name}" was installed in the smoke app\n`,
      );
    }
  }
  if (!fs.existsSync(modules)) {
    process.stderr.write("pack:smoke warning: node_modules missing after install\n");
  }
}

function main() {
  const tmpdir = fs.mkdtempSync(path.join(os.tmpdir(), "edge-mesh-pack-smoke-"));
  try {
    const packOut = run("npm", ["pack", "--json", "--pack-destination", tmpdir], REPO_ROOT);
    const packed = parsePack(packOut);
    if (!packed?.filename) throw new Error("npm pack did not report a tarball filename");

    const tarball = path.join(tmpdir, packed.filename);
    const bytes = fs.statSync(tarball).size;

    const appDir = path.join(tmpdir, "app");
    fs.mkdirSync(appDir, { recursive: true });
    fs.writeFileSync(
      path.join(appDir, "package.json"),
      `${JSON.stringify({ name: "smoke", private: true, type: "module" }, null, 2)}\n`,
    );

    run(
      "npm",
      [
        "install",
        tarball,
        "--no-audit",
        "--no-fund",
        "--omit=optional",
        "--loglevel=error",
      ],
      appDir,
    );

    const packages = countInstalled(appDir);
    assertOptionalPeersAbsent(appDir);

    let counts;
    try {
      counts = run("node", ["--input-type=module", "-e", PROBE], appDir);
    } catch (error) {
      process.stderr.write(`pack:smoke: smoke import failed\n${error.stderr ?? error.message}\n`);
      return 1;
    }

    const line = counts.trim().split("\n").pop();
    const [webCount, trustCount] = line.trim().split(/\s+/).map(Number);
    if (!Number.isFinite(webCount) || !Number.isFinite(trustCount) || webCount === 0 || trustCount === 0) {
      process.stderr.write(`pack:smoke: unexpected export counts: ${line}\n`);
      return 1;
    }

    process.stdout.write(
      `pack:smoke ok tarball=${packed.filename} bytes=${bytes} packages=${packages} web_exports=${webCount} trust_exports=${trustCount}\n`,
    );
    return 0;
  } finally {
    fs.rmSync(tmpdir, { recursive: true, force: true });
  }
}

process.exitCode = main();