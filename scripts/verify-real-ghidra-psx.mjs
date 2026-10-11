#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../dist/domain/evidence.js";
import { parseAnalysisSnapshot } from "../dist/domain/analysisSnapshot.js";
import { requireMcpOperationResult } from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

// Source-owned fixture, no Sony/game code and no target execution or installation.
if (!process.env.GHIDRA_INSTALL_DIR)
  throw new Error("Set GHIDRA_INSTALL_DIR to an existing installation");
const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-psx-proof-"));
const path = join(workspace, "source-owned.psx");
const snapshotPath = join(workspace, "snapshot.json");
const bytes = Buffer.alloc(4096);
bytes.write("PS-X EXE");
for (const [offset, value] of [
  [0x10, 0x80010010],
  [0x14, 0x80010100],
  [0x18, 0x80010000],
  [0x1c, 2048],
  [0x28, 0x80010800],
  [0x2c, 64],
  [0x30, 0x801fff00],
  [0x34, 0xf0],
])
  bytes.writeUInt32LE(value, offset);
// addiu v0,a0,1; jr ra; nop. Entry deliberately differs from load base.
[0x24820001, 0x03e00008, 0].forEach((word, i) =>
  bytes.writeUInt32LE(word, 0x810 + i * 4),
);
await writeFile(path, bytes);
const sha256 = createHash("sha256").update(bytes).digest("hex");
const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const env = {
  PATH: process.env.PATH,
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  REA_PROCESS_RUN_ID: run.run_id,
  GHIDRA_INSTALL_DIR: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME ? { JAVA_HOME: process.env.JAVA_HOME } : {}),
};
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env,
  stderr: "pipe",
});
const client = new Client({ name: "rea-psx-proof", version: "1" });
const call = async (name, args = {}) =>
  requireMcpOperationResult(
    await client.callTool({ name, arguments: args }, undefined, {
      timeout: 180000,
    }),
    name,
  );
let failure;
let report;
try {
  await client.connect(transport);
  const target = await call("open_binary", { path, provider_id: "ghidra" });
  assert.equal(target.sha256, sha256);
  assert.equal(target.format, "psx-exe");
  const memory = await call("read_bytes", {
    address: "0x80010010",
    length: 12,
  });
  assert.equal(memory.bytes_hex, bytes.subarray(0x810, 0x81c).toString("hex"));
  const mapping = await call("address_to_file_offset", {
    address: "0x80010010",
  });
  assert.equal(mapping.file_offset, 0x810);
  const instruction = await call("inspect_native_instruction", {
    address: "0x80010010",
  });
  assert.match(JSON.stringify(instruction), /addiu/i);
  const dossier = await call("analyze_function", { procedure: "0x80010010" });
  assert.ok(dossier.pseudocode.trim().length);
  await call("close_binary", { snapshot_path: snapshotPath });
  const snapshot = parseAnalysisSnapshot(
    JSON.parse(await readFile(snapshotPath, "utf8")),
  );
  assert.equal(snapshot.target.format, "psx-exe");
  assert.equal(
    snapshot.binding.analysis_profile.parameters.psx_exe.entryPoint,
    0x80010010,
  );
  assert.equal(
    snapshot.binding.analysis_profile.parameters.psx_exe.stackOffset,
    0xf0,
  );
  assert.equal(
    snapshot.binding.analysis_profile.parameters.language_id,
    "MIPS:LE:32:default",
  );
  await call("open_binary", {
    path,
    provider_id: "ghidra",
    snapshot_path: snapshotPath,
  });
  assert.equal(
    (await call("read_bytes", { address: "0x80010010", length: 12 })).bytes_hex,
    memory.bytes_hex,
  );
  await call("close_binary");
  const cli = await promisify(execFile)(
    process.execPath,
    [
      entrypoint,
      "function",
      path,
      "0x80010010",
      "--provider",
      "ghidra",
      "--json",
    ],
    { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
  );
  const evidence = parseEvidence(JSON.parse(cli.stdout));
  assert.equal(evidence.subject.digest.sha256, sha256);
  assert.equal(evidence.subject.format, "psx-exe");
  assert.equal(
    evidence.normalized_result.procedure.address,
    dossier.procedure.address,
  );
  assert.equal(
    createHash("sha256")
      .update(await readFile(path))
      .digest("hex"),
    sha256,
  );
  report = {
    status: "passed",
    lane: "psx-exe-r3000a-static-v1",
    sha256,
    evidence_id: evidence.evidence_id,
    entry: dossier.procedure.address,
    source_file_offset: mapping.file_offset,
    snapshot_replay: true,
    limitations: [
      "Generic MIPS static decoder; GTE and load-delay execution unverified",
    ],
  };
} catch (cause) {
  failure = cause;
} finally {
  await client.close();
  await transport.close();
}

const completed = await completeVerifierRun(run);
if (
  completed.process_lineage.status !== "verified" ||
  completed.process_lineage.descendants.length !== 0
)
  throw new Error(
    `Cleanup unverified; retained diagnostic workspace: ${workspace}`,
    { cause: failure },
  );
if (failure !== undefined)
  throw new Error(
    `PS-X verification failed; retained workspace: ${workspace}`,
    { cause: failure },
  );
await rm(workspace, { recursive: true, force: true });
console.log(JSON.stringify({ ...completed, ...report }, null, 2));
