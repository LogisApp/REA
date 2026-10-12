import { describe, expect, it } from "vitest";

import {
  ADD_PEOPLE_LEFT,
  ADD_PEOPLE_RIGHT,
  INITIALIZE_PEOPLE_LEFT,
  INITIALIZE_PEOPLE_RIGHT,
  USE_GADGET_LEFT,
  USE_GADGET_RIGHT,
  wallaceDossier,
} from "./functionComparisonNormalizedViews.fixture.js";
import { compareFunctions } from "./functionComparison.js";
import { functionComparisonResultSchema } from "./functionComparisonSchemas.js";
import { createEvidence, type Evidence } from "./evidence.js";
import { createEvidenceBundle } from "./evidenceBundle.js";
import { findChangedBehavior } from "./changedBehavior.js";
import { verifyReconstruction } from "./reconstructionVerification.js";
import { correlateStaticAndRuntime } from "./staticRuntimeCorrelation.js";
import { functionDossierSchema } from "./hopperValues.js";
import { jsonValueSchema } from "./jsonValue.js";
import { enhancedInputSchemas } from "../contracts/enhancedInputs.js";

const G_HIDRA = {
  id: "ghidra",
  name: "Ghidra",
  version: "12.1.4",
} as const;

const observe = (
  digest: string,
  dossier: object,
  provider: {
    readonly id: string;
    readonly name: string;
    readonly version: string;
  } = G_HIDRA,
): Evidence =>
  createEvidence(
    {
      path: `/tmp/wallace-${digest}`,
      sha256: digest.repeat(64),
      format: "pe",
      architecture: "x86",
    },
    provider,
    {
      operation: "analyze_function",
      parameters: enhancedInputSchemas.analyze_function.parse({
        procedure: "fixture",
      }),
      result: jsonValueSchema.parse(
        functionDossierSchema.parse(wallaceDossier(dossier)),
      ),
      confidence: "observed",
      authority: "shipped-artifact",
    },
  );

const capture = (digit: string): Evidence =>
  createEvidence(
    undefined,
    { id: "fixture", name: "Fixture", version: "1" },
    {
      predicateType: "rea.process-capture",
      operation: "capture_process_scenario",
      parameters: {},
      result: { digit },
      authority: "controlled-replay",
      environment: {
        id: `fixture-${digit}`,
        platform: "test",
        architecture: "test",
        isolation: "process",
      },
    },
  );

const addPeoplePair = () =>
  [observe("1", ADD_PEOPLE_LEFT), observe("2", ADD_PEOPLE_RIGHT)] as const;
const initializePeoplePair = () =>
  [
    observe("3", INITIALIZE_PEOPLE_LEFT),
    observe("4", INITIALIZE_PEOPLE_RIGHT),
  ] as const;
const gadgetPair = () =>
  [observe("5", USE_GADGET_LEFT), observe("6", USE_GADGET_RIGHT)] as const;

const dimension = (result: ReturnType<typeof compareFunctions>, name: string) =>
  result.dimensions.find((item) => item.dimension === name);

const view = (result: ReturnType<typeof compareFunctions>, name: string) =>
  result.normalized_views?.views.find((item) => item.dimension === name);

describe("wallace relocation-only function pair", () => {
  const [left, right] = addPeoplePair();

  it("keeps every exact dimension, count, and status unchanged by normalized views", () => {
    const exact = compareFunctions(left, right);
    const normalized = compareFunctions(left, right, {
      includeNormalizedViews: true,
    });
    expect(normalized.dimensions).toEqual(exact.dimensions);
    expect(normalized.changes).toEqual(exact.changes);
    expect(normalized.summary).toEqual(exact.summary);
    expect(normalized.status).toBe(exact.status);
    expect(functionComparisonResultSchema.safeParse(normalized).success).toBe(
      true,
    );
  });

  it("reports the unchanged source function as changed in the exact text dimensions", () => {
    const result = compareFunctions(left, right);
    expect(dimension(result, "pseudocode")).toMatchObject({
      status: "changed",
      left_count: 639,
      right_count: 639,
    });
    expect(dimension(result, "assembly")).toMatchObject({ status: "changed" });
    expect(dimension(result, "cfg")).toMatchObject({ status: "unchanged" });
  });

  it("separates the relocation-only change in both opt-in normalized views", () => {
    const result = compareFunctions(left, right, {
      includeNormalizedViews: true,
    });
    for (const name of ["pseudocode_normalized", "assembly_normalized"]) {
      const projection = view(result, name);
      expect(projection, name).toMatchObject({
        status: "unchanged",
        conclusion_kind: "derived_relationship",
        evidence_links: [left.evidence_id, right.evidence_id],
      });
      expect(projection?.masking?.rules.map(({ rule }) => rule)).toEqual([
        "address_derived_identifier",
        "function_relative_address",
        "corroborated_external_address",
      ]);
    }
  });

  it("masks the relocated call target and label, never the string literals or constants", () => {
    const result = compareFunctions(left, right, {
      includeNormalizedViews: true,
    });
    const projection = view(result, "pseudocode_normalized");
    // The function name plus six calls to the relocated thunk.
    expect(projection?.masking?.left).toMatchObject({
      address_derived_identifiers: 7,
      unmasked_address_derived_identifiers: 0,
      corroborated_addresses: 0,
      visible_addresses: 2,
    });
    expect(projection?.masking?.right).toMatchObject({
      address_derived_identifiers: 7,
      unmasked_address_derived_identifiers: 0,
      corroborated_addresses: 0,
      visible_addresses: 2,
    });
    // Every body address became an entry-relative offset, so the counts match.
    expect(projection?.left_count).toBe(projection?.right_count);
  });
});

describe("wallace edited function pairs", () => {
  it.each([
    ["initializePeople", initializePeoplePair],
    ["gadget function", gadgetPair],
  ] as const)("keeps %s changed in the normalized views", (_name, pair) => {
    const [before, after] = pair();
    const result = compareFunctions(before, after, {
      includeNormalizedViews: true,
    });
    expect(view(result, "pseudocode_normalized")).toMatchObject({
      status: "changed",
    });
    expect(view(result, "assembly_normalized")).toMatchObject({
      status: "changed",
    });
    expect(dimension(result, "pseudocode")).toMatchObject({
      status: "changed",
    });
  });

  it("keeps uncorroborated constants visible in normalized pseudocode", () => {
    const [before, after] = initializePeoplePair();
    const result = compareFunctions(before, after, {
      includeNormalizedViews: true,
    });
    const projection = view(result, "pseudocode_normalized");
    // `local_c % 3` and the dropped `rand()` call are ordinary text, so the
    // masked digests differ for the same reason the exact digests do.
    expect(projection?.left_digest).not.toBe(projection?.right_digest);
    // The debug-fill loop bounds stay readable on both sides.
    expect(projection?.masking?.left.visible_addresses).toBe(3);
    expect(projection?.masking?.right.visible_addresses).toBe(3);
  });
});

const syntheticDossier = (input: {
  readonly base: string;
  readonly name: string;
  readonly pseudocode: string;
  readonly assembly: readonly string[];
  readonly body?: boolean;
  readonly callees?: readonly {
    readonly address: string;
    readonly name: string;
    readonly thunk_target?: string;
  }[];
}) => ({
  procedure: {
    address: input.base,
    name: input.name,
    classification: null,
    body:
      input.body === false
        ? { available: false as const, reason: "extent not observed" }
        : {
            available: true as const,
            provenance: "fixture",
            ranges: [
              {
                start: input.base,
                end: `0x${(BigInt(input.base) + 0x20n).toString(16)}`,
              },
            ],
            total_bytes: 0x21,
            span_bytes: 0x21,
            non_contiguous: false,
            contains_entry: true,
          },
    signature: "int helper(void)",
    locals: [],
  },
  pseudocode: input.pseudocode,
  assembly: [...input.assembly],
  comments: [],
  callers: [],
  callees: (input.callees ?? []).map(({ address, name, thunk_target }) => ({
    address,
    name,
    classification:
      thunk_target === undefined
        ? null
        : {
            external: false,
            thunk: true,
            thunk_target,
            provenance: "fixture",
          },
    body: { available: false as const, reason: "extent not observed" },
  })),
  incoming_references: [],
  outgoing_references: [],
  referenced_strings: [],
  referenced_names: [],
  basic_blocks: [
    {
      start: input.base,
      end: `0x${(BigInt(input.base) + 0x20n).toString(16)}`,
      successors: [],
    },
  ],
  native_api: null,
  native_value_flow: null,
  limitations: [],
});

const syntheticPair = (
  left: object,
  right: object,
  rightProvider: {
    readonly id: string;
    readonly name: string;
    readonly version: string;
  } = G_HIDRA,
) => [observe("7", left), observe("8", right, rightProvider)] as const;

const relocatedText = (
  address: string,
  options: { readonly body?: boolean } = {},
) => {
  const own = `FUN_${BigInt(address).toString(16).padStart(8, "0")}`;
  return syntheticDossier({
    base: address,
    name: own,
    pseudocode: `void ${own}(void) {\n  thunk_FUN_00411860(index % 3);\n  if (strcmp(a,"b") == 0) return;\n  stack:0xffffffffffffff3c;\n}\n`,
    assembly: [`${address}: PUSH EBP`, `${address}: CALL 0x00411195`],
    callees: [
      {
        address: "0x411195",
        name: "thunk_FUN_00411860",
        thunk_target: "0x411860",
      },
    ],
    ...options,
  });
};

const relocatedPseudocode = (address: string, body: string) =>
  `void FUN_${BigInt(address).toString(16).padStart(8, "0")}(void) { ${body}; }`;

describe("normalized view edge cases", () => {
  it("reports a relocated pair as unchanged without touching exact statuses", () => {
    const [left, right] = syntheticPair(
      relocatedText("0x411700"),
      relocatedText("0x4116f0"),
    );
    const result = compareFunctions(left, right, {
      includeNormalizedViews: true,
    });
    expect(
      result.dimensions.map(({ dimension, status }) => [dimension, status]),
    ).toEqual(
      expect.arrayContaining([
        ["assembly", "changed"],
        ["cfg", "unchanged"],
      ]),
    );
    expect(view(result, "pseudocode_normalized")).toMatchObject({
      status: "unchanged",
    });
    expect(view(result, "assembly_normalized")).toMatchObject({
      status: "unchanged",
    });
  });

  it.each([
    ["a small numeric constant", "index % 3", "index % 5"],
    ["a mnemonic", "index % 3", "index % 4"],
    ["a named symbol", 'strcmp(a,"b")', 'strlen(a,"b")'],
    ["a literal", '"b"', '"c"'],
    ["an uncorroborated address-derived label", "FUN_00411700", "FUN_00c0ffee"],
    ["a non-default address space", "stack:0xffff00", "stack:0xffff08"],
  ])("keeps a changed %s visible", (_name, from, to) => {
    const [left, right] = syntheticPair(
      {
        ...relocatedText("0x411700"),
        pseudocode: relocatedPseudocode("0x411700", from),
      },
      {
        ...relocatedText("0x4116f0"),
        pseudocode: relocatedPseudocode("0x4116f0", to),
      },
    );
    const result = compareFunctions(left, right, {
      includeNormalizedViews: true,
    });
    expect(view(result, "pseudocode_normalized")).toMatchObject({
      status: "changed",
    });
  });

  it("leaves an unobserved function extent masked by ordinal and reports it", () => {
    const [left, right] = syntheticPair(
      relocatedText("0x411700", { body: false }),
      relocatedText("0x4116f0"),
    );
    const result = compareFunctions(left, right, {
      includeNormalizedViews: true,
    });
    expect(view(result, "pseudocode_normalized")).toMatchObject({
      status: "unchanged",
      limitations: expect.arrayContaining([
        expect.stringContaining("did not observe its own function body extent"),
      ]),
    });
    expect(view(result, "assembly_normalized")).toMatchObject({
      status: "unchanged",
    });
  });

  it("leaves provider-specific text unresolved in both views", () => {
    const [left, right] = syntheticPair(
      relocatedText("0x411700"),
      relocatedText("0x4116f0"),
      { id: "ida", name: "IDA", version: "9.1" },
    );
    const result = compareFunctions(left, right, {
      includeNormalizedViews: true,
    });
    for (const name of ["pseudocode_normalized", "assembly_normalized"]) {
      expect(view(result, name)).toMatchObject({
        status: "unknown",
        masking: null,
        conclusion_kind: "unresolved_branch",
        limitations: expect.arrayContaining([
          expect.stringContaining("requires one provider identity"),
        ]),
      });
    }
    expect(result.summary).toMatchObject({ unknown: 3 });
  });

  it("omits normalized views unless the caller opts in", () => {
    const [left, right] = syntheticPair(
      relocatedText("0x411700"),
      relocatedText("0x4116f0"),
    );
    expect(compareFunctions(left, right).normalized_views).toBeUndefined();
  });
});

const comparisonEvidence = (
  left: Evidence,
  right: Evidence,
  includeNormalizedViews: boolean,
): Evidence =>
  createEvidence(
    undefined,
    {
      id: "rea-function-comparison",
      name: "REA function comparison",
      version: "1",
    },
    {
      predicateType: "rea.function-comparison",
      operation: "compare_functions",
      parameters: {
        left_evidence_id: left.evidence_id,
        right_evidence_id: right.evidence_id,
        ...(includeNormalizedViews ? { include_normalized_views: true } : {}),
      },
      result: jsonValueSchema.parse(
        compareFunctions(left, right, { includeNormalizedViews }),
      ),
      confidence: "derived",
      authority: "analyst-inference",
      evidenceLinks: [left.evidence_id, right.evidence_id],
    },
  );

const claim = (dimension: string, evidence: Evidence) => ({
  name: "Relocated function",
  claims: [
    {
      kind: "structural-function" as const,
      claim_id: "normalized",
      title: "Address-normalized pseudocode agrees",
      comparison_evidence_id: evidence.evidence_id,
      dimension,
    },
  ],
});

describe("normalized view consumers", () => {
  const [relocatedLeft, relocatedRight] = addPeoplePair();
  const [editedLeft, editedRight] = initializePeoplePair();

  it("verifies a declared normalized claim from the requested view", () => {
    const evidence = comparisonEvidence(relocatedLeft, relocatedRight, true);
    const bundle = createEvidenceBundle([
      relocatedLeft,
      relocatedRight,
      evidence,
    ]);
    const result = verifyReconstruction(
      claim("pseudocode_normalized", evidence),
      bundle,
    );
    expect(result.claims.items).toMatchObject([
      {
        status: "pass",
        observed_status: "unchanged",
        dimension: "pseudocode_normalized",
      },
    ]);
  });

  it("rejects a normalized claim the comparison never produced", () => {
    const evidence = comparisonEvidence(relocatedLeft, relocatedRight, false);
    const bundle = createEvidenceBundle([
      relocatedLeft,
      relocatedRight,
      evidence,
    ]);
    expect(() =>
      verifyReconstruction(claim("pseudocode_normalized", evidence), bundle),
    ).toThrow(/normalized view was not requested/u);
  });

  it("keeps relocation-only comparisons free of normalized findings", () => {
    const findings = findChangedBehavior([
      comparisonEvidence(relocatedLeft, relocatedRight, true),
    ]).findings.items;
    expect(findings.map(({ dimension }) => dimension)).not.toContain(
      "pseudocode_normalized",
    );
    expect(findings.map(({ dimension }) => dimension)).toContain("pseudocode");
  });

  it("reports a normalized change as its own static candidate", () => {
    const findings = findChangedBehavior([
      comparisonEvidence(editedLeft, editedRight, true),
    ]).findings.items;
    expect(findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          dimension: "pseudocode_normalized",
          status: "changed",
        }),
      ]),
    );
  });

  it("selects a normalized view for a static/runtime hypothesis", () => {
    const staticEvidence = comparisonEvidence(editedLeft, editedRight, true);
    const runtime = createEvidence(
      undefined,
      {
        id: "rea-process",
        name: "REA deterministic process harness",
        version: "3",
      },
      {
        predicateType: "rea.process-comparison",
        operation: "compare_process_captures",
        parameters: {
          left_evidence_id: capture("1").evidence_id,
          right_evidence_id: capture("2").evidence_id,
        },
        result: {
          status: "changed",
          terminal: "changed",
          interaction: "unchanged",
          exit: "unchanged",
          filesystem: "unchanged",
          process: "unchanged",
          first_divergence: {
            status: "found",
            dimension: "terminal",
            index: 0,
            left_at_ms: 0,
            right_at_ms: 0,
            left: "left",
            right: "right",
          },
          limitations: [],
        },
        confidence: "derived",
        authority: "analyst-inference",
        evidenceLinks: [capture("1").evidence_id, capture("2").evidence_id],
      },
    );
    const correlate = (dimension: string) =>
      correlateStaticAndRuntime({
        static_comparisons: [staticEvidence],
        runtime_comparisons: [runtime],
        mappings: [
          {
            static: {
              comparison_evidence_id: staticEvidence.evidence_id,
              selector: { kind: "function", dimension },
            },
            runtime: {
              comparison_evidence_id: runtime.evidence_id,
              dimension: "terminal",
            },
            side_alignment: "left_to_left",
            hypothesis: {
              statement:
                "The static edit is associated with terminal behavior.",
              expected_pattern: "cochanged",
            },
          },
        ],
      });
    expect(correlate("pseudocode_normalized").correlations.items).toMatchObject(
      [{ observed_pattern: "cochanged", classification: "hypothesis" }],
    );
    expect(correlate("pseudocode")).toMatchObject({ status: "correlated" });
  });
});
