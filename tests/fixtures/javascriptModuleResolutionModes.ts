import { createHash } from "node:crypto";
import { expect } from "vitest";
import type { analyzeJavaScriptDirectory } from "../support/cli/javascriptApplication.js";

const inlineSource = [
  'type Imported = import("cts-package", { with: { "resolution-mode": "import" } }).ImportOnly;',
  'type Required = import("cts-package", { with: { "resolution-mode": "require" } }).RequireOnly;',
  'type Nested = import("cts-package", { with: { "resolution-mode": "import" } }).Shapes.ImportOnly;',
  'const nested: Nested = { source: "nested-import" };',
  'type ExportedNamespace = import("./reexport.cjs").Types.ImportOnly;',
  'const namespace: ExportedNamespace = { source: "import" };',
  'const first: Imported = { source: "import" };',
  'const second: Required = { source: "require" };',
  "console.log(JSON.stringify([first.source, second.source, nested.source, namespace.source]));",
].join("\n");
const recoveredSource = [
  'type Valid = import("cts-package", { with: { "resolution-mode": "import" } }).ImportOnly;',
  "type Broken = import(Unknown).T;",
].join("\n");
const sameSource = [
  'import type { SameType as First } from "same-mode" with { "resolution-mode": "import" };',
  'import type { SameType as Second } from "same-mode" with { "resolution-mode": "require" };',
].join("\n");
const unresolvedSource = [
  'import type { Missing as First } from "missing-mode" with { "resolution-mode": "import" };',
  'import type { Missing as Second } from "missing-mode" with { "resolution-mode": "require" };',
].join("\n");
const nativeSource = [
  'import type { NativeMode as Required } from "native-mode/addon.node" with { "resolution-mode": "require" };',
  'import type { NativeMode as Imported } from "native-mode/addon.node" with { "resolution-mode": "import" };',
  'export type { NativeMode as NativeReexport } from "native-mode/addon.node" with { "resolution-mode": "require" };',
  'export type * from "native-mode/addon.node" with { "resolution-mode": "import" };',
  'const first: Required = { source: "require" };',
  'const second: Imported = { source: "import" };',
  "console.log(JSON.stringify([first.source, second.source]));",
].join("\n");
export const modeSourceFiles = {
  "cts/inline.cts": inlineSource,
  "cts/script.ts": inlineSource,
  "cts/same.cts": sameSource,
  "cts/unresolved.cts": unresolvedSource,
  "cts/native.mts": nativeSource,
  "cts/recovered.cts": recoveredSource,
};

export const modePackageFiles = {
  "node_modules/same-mode/package.json": JSON.stringify({
    exports: { import: "./both.js", require: "./both.js" },
  }),
  "node_modules/same-mode/both.js": "module.exports = {};",
  "node_modules/same-mode/both.d.ts": "export interface SameType {}",
  "node_modules/native-mode/package.json": JSON.stringify({
    exports: {
      "./addon.node": {
        require: { types: "./require.d.cts", default: "./require.node" },
        import: { types: "./import.d.mts", default: "./import.node" },
      },
    },
  }),
  "node_modules/native-mode/require.d.cts":
    'export interface NativeMode { source: "require"; }',
  "node_modules/native-mode/import.d.mts":
    'export interface NativeMode { source: "import"; }',
  // Opaque inventory fixtures: resolve their paths, never execute native code.
  "node_modules/native-mode/require.node": "source-owned native placeholder",
  "node_modules/native-mode/import.node": "source-owned native placeholder",
};

export const expectReviewModeEvidence = (
  graph: Awaited<ReturnType<typeof analyzeJavaScriptDirectory>>["graph"],
): void => {
  const sourceEdges = (source: string) =>
    graph.edges.filter(
      ({ evidence }) =>
        evidence.location.available &&
        evidence.location.value.kind === "source-range" &&
        evidence.location.value.source === source,
    );
  for (const [source, text, target] of [
    ["cts/same.cts", sameSource, "node_modules/same-mode/both.js"],
    ["cts/unresolved.cts", unresolvedSource, null],
  ] as const) {
    const links = sourceEdges(source).filter(
      ({ properties }) =>
        properties.module_link_kind === "import" ||
        properties.kind === "static-import",
    );
    for (const mode of ["import", "require"])
      expect
        .soft(
          links.filter(({ properties }) => properties.resolution_mode === mode),
        )
        .toMatchObject([
          {
            properties: { resolved_path: target },
            evidence: {
              artifact: {
                sha256: createHash("sha256").update(text).digest("hex"),
              },
            },
          },
          {
            properties: { resolved_path: target },
            evidence: {
              artifact: {
                sha256: createHash("sha256").update(text).digest("hex"),
              },
            },
          },
        ]);
  }
  expectInlineTypeEvidence(graph);
  expectRecoveredTypeEvidence(graph);
  const native = graph.nodes
    .flatMap(({ observations }) => observations)
    .filter(
      ({ properties, evidence }) =>
        properties.specifier === "native-mode/addon.node" &&
        "native_export_verification" in properties &&
        evidence.location.available &&
        evidence.location.value.kind === "source-range" &&
        evidence.location.value.source === "cts/native.mts",
    );
  for (const [line, mode] of [
    [1, "require"],
    [2, "import"],
    [3, "require"],
    [4, "import"],
  ] as const)
    expect.soft(native).toContainEqual(
      expect.objectContaining({
        properties: expect.objectContaining({
          resolved_path: `node_modules/native-mode/${mode}.node`,
          native_export_verification: "not-performed",
        }),
        evidence: expect.objectContaining({
          artifact: expect.objectContaining({
            sha256: createHash("sha256").update(nativeSource).digest("hex"),
          }),
          location: expect.objectContaining({
            value: expect.objectContaining({
              start: expect.objectContaining({ line }),
            }),
          }),
        }),
      }),
    );
};

const expectInlineTypeEvidence = (
  graph: Awaited<ReturnType<typeof analyzeJavaScriptDirectory>>["graph"],
): void => {
  for (const source of ["cts/inline.cts", "cts/script.ts"]) {
    for (const [line, mode, target, path] of [
      [1, "import", "decoy.mjs", ["ImportOnly"]],
      [2, "require", "actual.cjs", ["RequireOnly"]],
      [3, "import", "decoy.mjs", ["Shapes", "ImportOnly"]],
    ] as const) {
      const links = graph.edges.filter(
        ({ properties, evidence }) =>
          (properties.module_link_kind === "type-import" ||
            properties.kind === "type-import") &&
          evidence.location.available &&
          evidence.location.value.kind === "source-range" &&
          evidence.location.value.source === source &&
          evidence.location.value.start.line === line,
      );
      expect.soft(links).toHaveLength(2);
      for (const link of links)
        expect.soft(link).toMatchObject({
          properties: {
            resolved_path: "node_modules/cts-package/" + target,
            resolution_mode: mode,
          },
          evidence: {
            artifact: {
              sha256: createHash("sha256").update(inlineSource).digest("hex"),
            },
          },
        });
      expect
        .soft(
          links.filter(
            ({ properties }) => properties.module_link_kind === "type-import",
          ),
        )
        .toMatchObject([
          { properties: { imported_name: path.at(-1), imported_path: path } },
        ]);
    }
  }
  expect
    .soft(graph.nodes.flatMap(({ observations }) => observations))
    .toContainEqual(
      expect.objectContaining({
        properties: expect.objectContaining({
          semantic_role: "source-module",
          path: "cts/script.ts",
          module_format: "unknown",
        }),
      }),
    );
};

const expectRecoveredTypeEvidence = (
  graph: Awaited<ReturnType<typeof analyzeJavaScriptDirectory>>["graph"],
): void => {
  expect.soft(graph.coverage.status).toBe("partial");
  expect
    .soft(graph.nodes.flatMap(({ observations }) => observations))
    .toContainEqual(
      expect.objectContaining({
        properties: expect.objectContaining({
          path: "cts/recovered.cts",
          parse_status: "partial",
        }),
      }),
    );
  const valid = graph.edges.filter(
    ({ properties, evidence }) =>
      (properties.module_link_kind === "type-import" ||
        properties.kind === "type-import") &&
      properties.specifier === "cts-package" &&
      evidence.location.available &&
      evidence.location.value.kind === "source-range" &&
      evidence.location.value.source === "cts/recovered.cts",
  );
  expect.soft(valid).toHaveLength(2);
  for (const link of valid)
    expect.soft(link).toMatchObject({
      properties: {
        resolved_path: "node_modules/cts-package/decoy.mjs",
        resolution_mode: "import",
      },
      evidence: {
        artifact: {
          sha256: createHash("sha256").update(recoveredSource).digest("hex"),
        },
      },
    });
};
