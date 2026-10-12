import { ok as resultOk } from "../../../src/domain/result.js";
import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

import type {
  AnalysisClient,
  AnalysisOperation,
  AnalysisProvider,
  CapabilityDescriptor,
} from "../../../src/application/AnalysisProvider.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { BinarySession } from "../../../src/application/binary/BinarySession.js";
import { SessionProviderRouter } from "../../../src/application/binary/SessionProviderRouter.js";
import { AnalysisProviderRegistry } from "../../../src/application/binary/AnalysisProviderRegistry.js";
import { ARTIFACT_COMPARISON_EXAMPLE } from "../../../src/contracts/artifactComparisonExample.js";
import { PROCESS_CAPTURE_REFERENCE } from "../../../src/contracts/investigationExamples.js";
import { EMPTY_PROCESS_CAPTURE_EXAMPLE } from "../../../src/domain/process/processCaptureExample.js";
import { createEvidence } from "../../../src/domain/evidence.js";
import { createArtifactInspection } from "../../../src/domain/artifactInspection.js";
import { artifactInventoryResultSchema } from "../../../src/domain/artifactGraph.js";
import { jsonValueSchema } from "../../../src/domain/jsonValue.js";
import { createPromptCompletionSource } from "../../../src/server/promptCompletion.js";
import { observed } from "../../fixtures/analysisExecution.js";
import { createAnalysisProfile } from "../../../src/domain/analysisProfile.js";

let directory: string | undefined;

afterEach(async () => {
  if (directory !== undefined)
    await rm(directory, { recursive: true, force: true });
  directory = undefined;
});

describe("guided prompt completion from live analysis", () => {
  it("reads live documents and complete procedures without ambiguous names", async () => {
    const requests: Array<Readonly<Record<string, unknown>>> = [];
    const session = createTestBinarySession(() => client(requests), {
      resolveAnalysisProfile: () =>
        Promise.resolve(
          resultOk({
            profile: createAnalysisProfile(
              {
                id: "fixture",
                name: "Fixture analysis provider",
                version: "1",
              },
              { fixture: true },
            ),
          }),
        ),
    });
    directory = await createTestTempDirectory("rea-prompt-completion-");
    const target = join(directory, "fixture.hop");
    await writeFile(target, "fixture");
    expect((await session.open(target)).ok).toBe(true);
    const completion = createPromptCompletionSource(session, session);

    // Completion never cold-starts a deep provider (#2076): a fresh open only
    // runs `health`, so document/procedure completion stays empty with no
    // provider call until a real tool call warms the provider.
    expect(session.isOperationWarmed("list_documents")).toBe(false);
    expect(await completion.complete("document", "app")).toEqual([]);
    expect(await completion.complete("procedure", "")).toEqual([]);
    expect(requests).toEqual([]);

    expect((await session.execute("list_documents", {})).ok).toBe(true);
    expect(session.isOperationWarmed("list_documents")).toBe(true);
    expect(await completion.complete("document", "app")).toEqual([
      "App",
      "AppTests",
    ]);
    expect(
      await completion.complete("procedure", "", {
        arguments: { document: "App" },
      }),
    ).toEqual(["0x1000", "0x2000", "0x3000", "0x4000", "tail", "unique"]);
    expect(requests).toEqual([{ document: "App" }]);
    expect(await completion.complete("provider", "fix")).toEqual(["fixture"]);
    expect(await completion.complete("document", "x".repeat(4_097))).toEqual(
      [],
    );

    await session.close();
    expect(await completion.complete("document", "")).toEqual([]);
    expect(await completion.complete("procedure", "")).toEqual([]);
  });
});

describe("guided prompt completion without provider work", () => {
  it("never dispatches a provider operation for cold completion", async () => {
    const operations: string[] = [];
    const session = createTestBinarySession(
      () => ({
        execute(operation, parameters) {
          operations.push(operation);
          return client([]).execute(operation, parameters);
        },
        close: () => Promise.resolve(resultOk(null)),
      }),
      {
        resolveAnalysisProfile: () =>
          Promise.resolve(
            resultOk({
              profile: createAnalysisProfile(
                {
                  id: "fixture",
                  name: "Fixture analysis provider",
                  version: "1",
                },
                { fixture: true },
              ),
            }),
          ),
      },
    );
    directory = await createTestTempDirectory("rea-prompt-completion-");
    const target = join(directory, "fixture.hop");
    await writeFile(target, "fixture");
    expect((await session.open(target)).ok).toBe(true);
    // Open only runs the composite `health` probe, which answers without
    // creating a child: not even `health` reaches the deep provider.
    expect(operations).toEqual([]);

    const completion = createPromptCompletionSource(session, session);
    expect(await completion.complete("document", "")).toEqual([]);
    expect(await completion.complete("procedure", "")).toEqual([]);
    // No `list_documents`/`list_procedures` dispatch: the deep provider is
    // never started as a completion side effect.
    expect(operations).toEqual([]);

    await session.close();
  });
});

describe("guided prompt completion across providers", () => {
  it("keeps inventory completion cold after an auxiliary-provider call", async () => {
    const deepOperations: string[] = [];
    const auxiliaryOperations: string[] = [];
    const session = new BinarySession(
      SessionProviderRouter.selectable(new AnalysisProviderRegistry([]), [
        recordingProvider(
          { id: "deep", name: "Deep analysis provider", version: "1" },
          ["list_documents", "list_procedures"],
          deepOperations,
          (operation) =>
            Promise.resolve(
              observed(
                operation === "list_documents"
                  ? ["DeepDoc"]
                  : [{ address: "0x1", value: "deep-procedure" }],
              ),
            ),
        ),
        recordingProvider(
          {
            id: "auxiliary",
            name: "Auxiliary analysis provider",
            version: "1",
          },
          ["inspect_artifact"],
          auxiliaryOperations,
          () => Promise.resolve(observed(null)),
        ),
      ]),
    );
    directory = await createTestTempDirectory("rea-prompt-completion-");
    const target = join(directory, "fixture.hop");
    await writeFile(target, "fixture");
    expect((await session.open(target)).ok).toBe(true);
    const completion = createPromptCompletionSource(session, session);

    // An auxiliary call warms only its own provider: inventory completion
    // must stay cold and dispatch nothing to the deep provider.
    expect((await session.execute("inspect_artifact", {})).ok).toBe(true);
    expect(auxiliaryOperations).toEqual(["inspect_artifact"]);
    expect(session.isOperationWarmed("inspect_artifact")).toBe(true);
    expect(session.isOperationWarmed("list_documents")).toBe(false);
    expect(session.isOperationWarmed("list_procedures")).toBe(false);
    expect(await completion.complete("document", "")).toEqual([]);
    expect(await completion.complete("procedure", "")).toEqual([]);
    expect(deepOperations).toEqual([]);

    expect((await session.execute("list_documents", {})).ok).toBe(true);
    expect(session.isOperationWarmed("list_documents")).toBe(true);
    expect(await completion.complete("document", "deep")).toEqual(["DeepDoc"]);

    await session.close();
  });
});

describe("guided prompt completion from investigation records", () => {
  it("excludes process captures missing canonical executable identity", async () => {
    const session = createTestBinarySession(() => client([]));
    const {
      selected_executable_sha256: _selectedDigest,
      executable_identity: _identity,
      executable_sha256,
      ...legacyManifest
    } = EMPTY_PROCESS_CAPTURE_EXAMPLE.manifest;
    const legacyCapture = {
      ...EMPTY_PROCESS_CAPTURE_EXAMPLE,
      manifest: { ...legacyManifest, executable_sha256 },
    };
    const evidence = createEvidence(undefined, fixtureProvider, {
      operation: "capture_process_scenario",
      parameters: {},
      result: legacyCapture,
      confidence: "observed",
      authority: "controlled-replay",
      environment: fixtureEnvironment,
    });
    expect(session.recordEvidence(evidence).ok).toBe(true);
    const completion = createPromptCompletionSource(session, session);

    expect(
      await completion.complete("capture", evidence.evidence_id.slice(0, 8)),
    ).toEqual([]);

    await session.close();
  });

  it("projects only validated typed identifiers from the evidence ledger", async () => {
    const session = createTestBinarySession(() => client([]));
    const invalidCapture = createEvidence(undefined, fixtureProvider, {
      operation: "capture_process_scenario",
      parameters: {},
      result: {},
      confidence: "observed",
      authority: "controlled-replay",
      environment: fixtureEnvironment,
    });
    const invalidInventory = createEvidence(undefined, fixtureProvider, {
      operation: "fixture_inventory",
      parameters: {},
      result: ARTIFACT_COMPARISON_EXAMPLE.right.normalized_result,
      confidence: "observed",
      authority: "shipped-artifact",
    });
    const inventoryInspection = createArtifactInspection(
      ARTIFACT_COMPARISON_EXAMPLE.left,
    );
    const inventory = artifactInventoryResultSchema.parse(
      ARTIFACT_COMPARISON_EXAMPLE.left.normalized_result,
    );
    const inspectionEvidence = createEvidence(undefined, fixtureProvider, {
      operation: "inspect_artifact",
      parameters: {},
      result: jsonValueSchema.parse(inventoryInspection),
      confidence: "observed",
      authority: "shipped-artifact",
      evidenceLinks: inventoryInspection.evidence_links,
    });
    for (const evidence of [
      ARTIFACT_COMPARISON_EXAMPLE.left,
      inspectionEvidence,
      PROCESS_CAPTURE_REFERENCE,
      invalidCapture,
      invalidInventory,
    ])
      expect(session.recordEvidence(evidence).ok).toBe(true);
    const unknown = session.recordUnknown({
      question: "Which branch handles the fallback?",
      severity: "medium",
      domain: "control-flow",
      supporting_evidence_ids: [],
      contradicting_evidence_ids: [],
      required_authority: "analyst-inference",
      required_confidence: "derived",
      required_environment: null,
      recommended_probes: [],
      relationships: [],
    });
    if (!unknown.ok) throw unknown.error;
    const completion = createPromptCompletionSource(session, session);

    expect(await completion.complete("capture", "ev_")).toEqual([
      PROCESS_CAPTURE_REFERENCE.evidence_id,
    ]);
    expect(await completion.complete("manifest", "agm_")).toEqual([
      inventory.manifest.manifest_id,
    ]);
    expect(await completion.complete("occurrence", "occ_")).toEqual(
      inventory.occurrences.map(({ occurrence_id }) => occurrence_id),
    );
    expect(await completion.complete("unknown", "unk_")).toEqual([
      unknown.value.unknown_id,
    ]);

    const resolved = session.updateUnknown({
      unknown_id: unknown.value.unknown_id,
      expected_revision: unknown.value.revision,
      status: "resolved",
      severity: unknown.value.severity,
      supporting_evidence_ids: unknown.value.supporting_evidence_ids,
      contradicting_evidence_ids: unknown.value.contradicting_evidence_ids,
      required_authority: unknown.value.required_authority,
      required_confidence: unknown.value.required_confidence,
      required_environment: unknown.value.required_environment,
      recommended_probes: unknown.value.recommended_probes,
      relationships: unknown.value.relationships,
      resolution: {
        disposition: "withdrawn",
        rationale: "The requested fallback is outside the current scope.",
        evidence_ids: [],
      },
    });
    expect(resolved.ok).toBe(true);
    expect(await completion.complete("unknown", "")).toEqual([]);

    await session.close();
    expect(await completion.complete("evidence", "ev_")).toEqual([]);
  });

  it("deduplicates, case-folds, and returns deterministic live evidence IDs", async () => {
    const session = createTestBinarySession(() => client([]));
    for (let index = 149; index >= 0; index -= 1) {
      const evidence = createEvidence(undefined, fixtureProvider, {
        operation: `fixture-${String(index)}`,
        parameters: { index },
        result: index,
        confidence: "derived",
        authority: "analyst-inference",
      });
      expect(session.recordEvidence(evidence).ok).toBe(true);
      expect(session.recordEvidence(evidence).ok).toBe(true);
    }
    const completion = createPromptCompletionSource(session, session);
    const values = await completion.complete("evidence", "EV_");
    expect(values).toHaveLength(150);
    expect(values).toEqual([...values].sort());
  });
});

describe("guided prompt completion from complete inventories", () => {
  it("reads every procedure in one provider call", async () => {
    let calls = 0;
    const procedures = Array.from({ length: 6_000 }, (_, address) => ({
      address: `0x${address.toString(16).padStart(8, "0")}`,
      value: `procedure_${String(address)}`,
    }));
    const bounded = createPromptCompletionSource({
      execute(_operation, parameters) {
        calls += 1;
        expect(parameters).toEqual({});
        return Promise.resolve(observed(procedures));
      },
    });
    const values = await bounded.complete("procedure", "");
    expect(calls).toBe(1);
    expect(values).toHaveLength(12_000);
    expect(values).toContain("0x00000000");
  });

  it("normalizes Unicode prefixes while preserving distinct exact identifiers", async () => {
    const completion = createPromptCompletionSource({
      execute(operation) {
        return Promise.resolve(
          observed(
            operation === "list_documents"
              ? ["Ａpp", "App", "app", "Zulu"]
              : null,
          ),
        );
      },
    });
    expect(await completion.complete("document", "ＡＰ")).toEqual([
      "App",
      "app",
      "Ａpp",
    ]);

    const malformed = createPromptCompletionSource({
      execute: () => Promise.resolve(observed(["valid", 1])),
    });
    expect(await malformed.complete("document", "")).toEqual([]);
  });
});

const fixtureProvider = { id: "fixture", name: "Fixture", version: "1" };

interface SplitProviderIdentity {
  readonly id: string;
  readonly name: string;
  readonly version: string;
}

const splitProviderCapabilities = (
  provider: SplitProviderIdentity,
  operations: readonly Exclude<AnalysisOperation, "health">[],
): readonly CapabilityDescriptor[] =>
  operations.map((operation) => ({
    provider,
    operation,
    available: true,
    reason: null,
    cachePolicy: "live",
    effects: {
      mutatesArtifact: false,
      launchesProcess: false,
      mayShowUi: false,
      mayAccessNetwork: false,
      mayWriteFilesystem: false,
      changesPermissions: false,
      requiresRoot: false,
    },
    limitations: [],
  }));

const recordingProvider = (
  identity: SplitProviderIdentity,
  operations: readonly Exclude<AnalysisOperation, "health">[],
  executed: string[],
  respond: (operation: string) => ReturnType<AnalysisClient["execute"]>,
): AnalysisProvider => ({
  identity: () => identity,
  capabilities: () => splitProviderCapabilities(identity, operations),
  createClient: () => ({
    execute: (operation, parameters) => {
      executed.push(operation);
      return respond(operation);
    },
    close: () => Promise.resolve(resultOk(null)),
  }),
});
const fixtureEnvironment = {
  id: "fixture-linux",
  platform: "linux",
  architecture: "x86_64",
  isolation: "process" as const,
};

const client = (
  requests: Array<Readonly<Record<string, unknown>>>,
): AnalysisClient => ({
  execute(operation, parameters) {
    if (operation === "list_documents")
      return Promise.resolve(observed(["AppTests", "App", "App"]));
    if (operation === "list_procedures") {
      requests.push(parameters);
      return Promise.resolve(
        observed([
          { address: "0x1000", value: "duplicate" },
          { address: "0x2000", value: "unique" },
          { address: "0x3000", value: "duplicate" },
          { address: "0x4000", value: "tail" },
        ]),
      );
    }
    return Promise.resolve(observed(null));
  },
  close: () => Promise.resolve(resultOk(null)),
});
