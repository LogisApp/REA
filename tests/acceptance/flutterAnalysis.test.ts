import { createHash } from "node:crypto";
import { expect } from "vitest";
import { toolContract } from "../../src/contracts/toolContracts.js";
import { parseEvidence } from "../../src/domain/evidence.js";
import {
  aotFixtureImage,
  REFERENCE_HASH,
} from "../../src/flutter/FlutterBuild.fixture.js";
import {
  createFlutterApk,
  createDuplicateFlutterApk,
} from "../fixtures/flutterApk.js";
import { connectLocalToolsMcp } from "../fixtures/localToolsMcp.js";
import { parseMcpToolError } from "../fixtures/mcpToolError.js";
import { cliTest } from "../support/cli/cliFixture.js";

cliTest(
  "CLI and stdio MCP retain Flutter identity, selected ABI and duplicate-member refusals",
  async ({ cli }) => {
    const image = aotFixtureImage();
    Buffer.from("Login\0").copy(image, 0x2300);
    const path = await createFlutterApk("selected target.apk", [
      { path: "lib/arm64-v8a/libapp.so", bytes: image },
      {
        path: "lib/arm64-v8a/libflutter.so",
        bytes: Buffer.from("Android (test) clang version 9.0.8\0"),
      },
      { path: "lib/x86_64/libapp.so", bytes: image },
      {
        path: "lib/x86_64/libflutter.so",
        bytes: Buffer.from("Android (test) clang version 9.0.8\0"),
      },
    ]);
    const { call } = await connectLocalToolsMcp();
    for (const [name, abi] of [
      ["identify_flutter_build", undefined],
      ["inspect_dart_aot", undefined],
      ["inspect_dart_aot", "x86_64"],
    ] as const) {
      const result = await cli.run({
        arguments: [
          name.replaceAll("_", "-"),
          path,
          "--json",
          ...(abi === undefined ? [] : ["--abi", abi]),
        ],
      });
      expect(result.exitCode, result.stderr).toBe(0);
      const evidence = toolContract(name).outputSchema.parse(result.json);
      const response = await call(name, {
        path,
        ...(abi === undefined ? {} : { abi }),
      });
      expect(response.isError, JSON.stringify(response)).not.toBe(true);
      const mcp = parseEvidence(response.structuredContent);
      expect(mcp.normalized_result).toEqual(evidence.normalized_result);
      expect(mcp.subject).toEqual(evidence.subject);
      expect(mcp.subject).toMatchObject({
        local_path: path,
        format: "apk",
        digest: { sha256: evidence.normalized_result.target.sha256 },
      });
      expect(mcp.evidence_id).toBe(evidence.evidence_id);
      if (name === "inspect_dart_aot") {
        expect(evidence.normalized_result).toMatchObject({
          abi: abi ?? "arm64-v8a",
          libapp: {
            snapshot_hash: REFERENCE_HASH,
            sha256: createHash("sha256").update(image).digest("hex"),
          },
          string_pool: { class_like_tokens: expect.arrayContaining(["Login"]) },
        });
      }
    }
    const duplicate = await createDuplicateFlutterApk();
    for (const name of [
      "identify_flutter_build",
      "inspect_dart_aot",
    ] as const) {
      const result = await cli.run({
        arguments: [name.replaceAll("_", "-"), duplicate, "--json"],
      });
      expect(result.exitCode).toBe(1);
      const mcp = parseMcpToolError(await call(name, { path: duplicate }));
      expect(mcp.error).toEqual(result.json);
      expect(mcp.error).toMatchObject({
        code: "invalid_request",
        details: { issues: [{ message: expect.stringContaining(duplicate) }] },
      });
    }
  },
);
