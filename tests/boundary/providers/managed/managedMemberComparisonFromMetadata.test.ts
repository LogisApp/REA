import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  compareManagedMembers,
  managedMemberComparisonResultSchema,
} from "../../../../src/domain/managed/managedMemberComparison.js";
import { inspectManagedMembersBytes } from "../../../../src/dotnet/ManagedMemberInspector.js";
import {
  buildManagedPeFixture,
  managedPeFixtureTarget,
} from "../../../../src/dotnet/ManagedPe.fixture.js";

describe("managed member comparison", () => {
  it("remaps renamed methods by exact CIL/signature without using names", () => {
    const leftBytes = buildManagedPeFixture();
    const rightBytes = buildManagedPeFixture({
      mvid: Buffer.from("00112233445566778899aabbccddeefe", "hex"),
      typeName: "A",
      typeNamespace: "X",
      methodName: "b",
      fieldName: "c",
    });
    const left = inspect(leftBytes, "/tmp/left.dll");
    const right = inspect(rightBytes, "/tmp/right.dll");
    const result = compareManagedMembers(
      { evidenceId: left.evidenceId, result: left.result },
      { evidenceId: right.evidenceId, result: right.result },
    );

    expect(result.algorithm.name_matching).toBe("exact-signature-fallback");
    expect(result.left.mvid).toBe("00112233-4455-6677-8899-aabbccddeeff");
    expect(result.right.mvid).toBe("33221100-5544-7766-8899-aabbccddeefe");
    expect(result.matching.exact_il_signature).toBe(1);
    expect(result.methods).toEqual([
      expect.objectContaining({
        status: "unchanged",
        left: expect.objectContaining({ token: "0x06000001", name: "Main" }),
        right: expect.objectContaining({ token: "0x06000001", name: "b" }),
        match: expect.objectContaining({
          status: "matched",
          basis: "exact-il-signature",
          confidence: "exact",
        }),
        dimensions: [],
      }),
    ]);
    expect(result.limitations).toContain(
      "Methods pair by declared type, name, and exact CIL/signature, then declared type, name, and signature, then exact CIL/signature or structural shape alone; a pair across declared types or names is not made while either member's own declared type and name remain unpaired on the other side, and names alone are never a matching basis.",
    );
    expect(
      managedMemberComparisonResultSchema.safeParse({
        ...result,
        limitations: Array.from({ length: 101 }, () => "x".repeat(4_097)),
      }).success,
    ).toBe(true);
  });

  it("compares changed CIL after pairing by exact signature", () => {
    const leftBytes = buildManagedPeFixture();
    const rightBytes = buildManagedPeFixture({
      ilBody: Buffer.from([
        0x32, 0x02, 0x7b, 0x02, 0x00, 0x00, 0x04, 0x28, 0x02, 0x00, 0x00, 0x0a,
        0x2a,
      ]),
    });
    const left = inspect(leftBytes, "/tmp/left.dll");
    const right = inspect(rightBytes, "/tmp/right.dll");
    const result = compareManagedMembers(
      { evidenceId: left.evidenceId, result: left.result },
      { evidenceId: right.evidenceId, result: right.result },
    );

    expect(result.matching.exact_il_signature).toBe(0);
    expect(result.matching.exact_signature).toBe(1);
    expect(result.methods[0]).toMatchObject({
      status: "changed",
      match: { status: "matched", basis: "exact-signature" },
      dimensions: ["cil"],
    });
  });

  it("rejects member states that disagree with their observed sides or match", () => {
    const left = inspect(buildManagedPeFixture(), "/tmp/left.dll");
    const right = inspect(buildManagedPeFixture(), "/tmp/right.dll");
    const result = compareManagedMembers(
      { evidenceId: left.evidenceId, result: left.result },
      { evidenceId: right.evidenceId, result: right.result },
    );
    const method = result.methods[0];
    expect(method).toBeDefined();
    if (method === undefined) return;

    expect(
      managedMemberComparisonResultSchema.safeParse({
        ...result,
        methods: [{ ...method, status: "unchanged", right: null }],
      }).success,
    ).toBe(false);
    expect(
      managedMemberComparisonResultSchema.safeParse({
        ...result,
        methods: [
          {
            ...method,
            match: {
              ...method.match,
              basis: "none",
              confidence: "unknown",
            },
          },
        ],
      }).success,
    ).toBe(false);
  });
});

describe("managed member comparison uncertainty", () => {
  it("does not infer a structural method match from undecoded signature fields", () => {
    const left = inspect(
      buildManagedPeFixture({ methodSignature: Buffer.from([0xff]) }),
      "/tmp/unknown-left.dll",
    );
    const right = inspect(
      buildManagedPeFixture({ methodSignature: Buffer.from([0xfe]) }),
      "/tmp/unknown-right.dll",
    );
    expect(left.result.methods[0]?.signature.parse_status).not.toBe("decoded");
    expect(right.result.methods[0]?.signature.parse_status).not.toBe("decoded");
    const result = compareManagedMembers(
      {
        evidenceId: left.evidenceId,
        result: {
          ...left.result,
          coverage: { ...left.result.coverage, state: "partial" },
        },
      },
      {
        evidenceId: right.evidenceId,
        result: {
          ...right.result,
          coverage: { ...right.result.coverage, state: "partial" },
        },
      },
    );
    expect(result.matching.structural_method_shape).toBe(0);
    expect(result.methods).toHaveLength(2);
    expect(
      result.methods.every(
        ({ status, match }) =>
          status === "unknown" && match.status === "unmatched",
      ),
    ).toBe(true);
  });

  it("keeps unmatched members unknown when opposite metadata is incomplete", () => {
    const left = inspect(buildManagedPeFixture(), "/tmp/left-partial.dll");
    const right = inspect(buildManagedPeFixture(), "/tmp/right-partial.dll");
    const leftPartial = {
      ...left.result,
      fields: [],
      metadata: { ...left.result.metadata, status: "partial" as const },
      coverage: { ...left.result.coverage, state: "partial" as const },
    };
    const rightPartial = {
      ...right.result,
      methods: [],
      metadata: { ...right.result.metadata, status: "partial" as const },
      coverage: { ...right.result.coverage, state: "partial" as const },
    };
    const result = compareManagedMembers(
      { evidenceId: left.evidenceId, result: leftPartial },
      { evidenceId: right.evidenceId, result: rightPartial },
    );

    expect(result.summary).toMatchObject({
      added: 0,
      removed: 0,
      unknown: 2,
    });
    expect(result.methods[0]).toMatchObject({
      status: "unknown",
      left: { token: "0x06000001" },
      right: null,
      limitations: [
        expect.stringContaining("unknown-within-incomplete-metadata"),
      ],
    });
    expect(result.fields[0]).toMatchObject({
      status: "unknown",
      left: null,
      right: { token: "0x04000001" },
      limitations: [
        expect.stringContaining("unknown-within-incomplete-metadata"),
      ],
    });
    expect(result.coverage).toEqual({
      status: "partial",
      left_status: "partial",
      right_status: "partial",
    });
  });

  it("does not guess ambiguous field signature matches", () => {
    const left = inspect(buildManagedPeFixture(), "/tmp/left.dll");
    const leftField = left.result.fields[0];
    expect(leftField).toBeDefined();
    if (leftField === undefined) return;
    const duplicatedLeft = {
      ...left.result,
      fields: [
        leftField,
        {
          ...leftField,
          token: "0x04000002",
          name: "other",
        },
      ],
    };
    const right = inspect(buildManagedPeFixture(), "/tmp/right.dll");
    const rightField = right.result.fields[0];
    expect(rightField).toBeDefined();
    if (rightField === undefined) return;
    // Both right fields are renamed, so neither left field keeps its declared
    // identity and only the shared signature links them.
    const duplicatedRight = {
      ...right.result,
      fields: [
        { ...rightField, name: "moved" },
        {
          ...rightField,
          token: "0x04000002",
          name: "renamed",
        },
      ],
    };
    const result = compareManagedMembers(
      { evidenceId: left.evidenceId, result: duplicatedLeft },
      { evidenceId: right.evidenceId, result: duplicatedRight },
    );

    expect(result.matching.ambiguous).toBe(1);
    expect(result.fields).toEqual([
      expect.objectContaining({
        status: "unknown",
        match: expect.objectContaining({
          status: "ambiguous",
          basis: "field-signature",
          candidate_left_tokens: ["0x04000001", "0x04000002"],
          candidate_right_tokens: ["0x04000001", "0x04000002"],
        }),
      }),
    ]);
  });
});

describe("managed member comparison of undecoded signatures", () => {
  it("remaps renamed methods only when raw signatures and complete normalized IL match", () => {
    const signature = Buffer.from([0x00, 0x00, 0x7f]);
    const left = inspect(
      buildManagedPeFixture({ methodSignature: signature }),
      "/tmp/undecoded-method-before.dll",
    );
    const renamed = inspect(
      buildManagedPeFixture({
        methodSignature: signature,
        methodName: "renamed",
      }),
      "/tmp/undecoded-method-renamed.dll",
    );
    expect(left.result.methods[0]?.signature.parse_status).toBe("unsupported");
    expect(renamed.result.metadata.status).toBe("complete");
    expect(renamed.result.coverage.state).toBe("partial");

    const exact = compareManagedMembers(left, renamed);
    expect(exact.methods).toEqual([
      expect.objectContaining({
        status: "unchanged",
        match: expect.objectContaining({
          status: "matched",
          basis: "exact-il-signature",
          confidence: "exact",
        }),
      }),
    ]);
    expect(exact.summary).toMatchObject({ added: 0, removed: 0, unknown: 0 });

    const changedRaw = inspect(
      buildManagedPeFixture({
        methodSignature: Buffer.from([0x00, 0x00, 0x7e]),
        methodName: "renamed",
      }),
      "/tmp/undecoded-method-raw-changed.dll",
    );
    const changedBody = inspect(
      buildManagedPeFixture({
        methodSignature: signature,
        methodName: "renamed",
        ilBody: Buffer.from([0x2a]),
      }),
      "/tmp/undecoded-method-il-changed.dll",
    );
    for (const negative of [changedRaw, changedBody]) {
      const result = compareManagedMembers(left, negative);
      expect(result.methods).toHaveLength(2);
      expect(
        result.methods.every((method) => method.match.status !== "matched"),
      ).toBe(true);
    }
  });

  it("pairs undecoded signatures by exact declared type, name, and raw bytes", () => {
    const undecoded = {
      methodSignature: Buffer.from([0x00, 0x00, 0x7f]),
      fieldSignature: Buffer.from([0x06, 0x7f]),
    };
    const left = inspect(
      buildManagedPeFixture(undecoded),
      "/tmp/undecoded-left.dll",
    );
    const right = inspect(
      buildManagedPeFixture(undecoded),
      "/tmp/undecoded-right.dll",
    );
    expect(left.result.metadata.status).toBe("complete");
    expect(left.result.coverage.state).toBe("partial");
    expect(left.result.methods[0]?.signature.parse_status).toBe("unsupported");
    expect(left.result.fields[0]?.signature.parse_status).toBe("unsupported");
    const result = compareManagedMembers(left, right);
    expect(result.summary).toMatchObject({
      unchanged: 2,
      added: 0,
      removed: 0,
      unknown: 0,
    });
    expect(result.methods[0]?.match).toMatchObject({
      status: "matched",
      basis: "exact-il-signature",
    });
    expect(result.fields[0]?.match).toMatchObject({
      status: "matched",
      basis: "exact-signature",
    });
  });

  it("keeps unmatched undecoded members unknown with complete metadata inventories", () => {
    const left = inspect(
      buildManagedPeFixture({
        methodSignature: Buffer.from([0x00, 0x00, 0x7f]),
        fieldSignature: Buffer.from([0x06, 0x7f]),
      }),
      "/tmp/undecoded-before.dll",
    );
    const right = inspect(
      buildManagedPeFixture({
        methodSignature: Buffer.from([0x00, 0x00, 0x7e]),
        fieldSignature: Buffer.from([0x06, 0x7e]),
      }),
      "/tmp/undecoded-after.dll",
    );
    expect(right.result.metadata.status).toBe("complete");
    expect(right.result.coverage.state).toBe("partial");
    const result = compareManagedMembers(left, right);
    expect(result.summary).toMatchObject({ added: 0, removed: 0, unknown: 4 });
    for (const item of [...result.methods, ...result.fields])
      expect(item).toMatchObject({
        status: "unknown",
        match: { status: "unmatched" },
        limitations: [expect.stringContaining("signature-not-decoded")],
      });
  });

  it("keeps a decoded member unknown beside a same-named undecoded counterpart", () => {
    const left = inspect(buildManagedPeFixture(), "/tmp/decoded-before.dll");
    const right = inspect(
      buildManagedPeFixture({
        methodSignature: Buffer.from([0x00, 0x00, 0x7f]),
        fieldSignature: Buffer.from([0x06, 0x7f]),
      }),
      "/tmp/undecoded-after.dll",
    );
    expect(left.result.methods[0]?.signature.parse_status).toBe("decoded");
    expect(left.result.fields[0]?.signature.parse_status).toBe("decoded");
    expect(right.result.metadata.status).toBe("complete");
    expect(right.result.coverage.state).toBe("partial");
    const result = compareManagedMembers(left, right);
    expect(result.summary).toMatchObject({ added: 0, removed: 0, unknown: 4 });
    for (const item of [...result.methods, ...result.fields])
      expect(item).toMatchObject({
        status: "unknown",
        match: { status: "unmatched" },
        limitations: [
          expect.stringMatching(
            item.left === null
              ? /^signature-not-decoded:/
              : /^counterpart-signature-not-decoded: The right (method|field) inventory/,
          ),
        ],
      });
  });
});

describe("managed member comparison of ambiguous undecoded signatures", () => {
  it("keeps a decoded member unknown beside an ambiguous same-named undecoded group", () => {
    const undecoded = { methodSignature: Buffer.from([0x00, 0x00, 0x7f]) };
    const decoded = inspect(buildManagedPeFixture(), "/tmp/decoded.dll");
    const left = inspect(buildManagedPeFixture(undecoded), "/tmp/left.dll");
    const right = inspect(buildManagedPeFixture(undecoded), "/tmp/right.dll");
    const [undecodedMethod] = left.result.methods;
    const [decodedMethod] = decoded.result.methods;
    if (undecodedMethod === undefined || decodedMethod === undefined)
      throw new Error("Expected fixture methods");
    expect(decodedMethod.name).toBe(undecodedMethod.name);
    // One undecoded T.M on the left meets two identical undecoded T.M on the
    // right, so that group stays ambiguous; the left also has a decoded T.M.
    const result = compareManagedMembers(
      {
        ...left,
        result: {
          ...left.result,
          methods: [undecodedMethod, { ...decodedMethod, token: "0x06000002" }],
        },
      },
      {
        ...right,
        result: {
          ...right.result,
          methods: [
            undecodedMethod,
            { ...undecodedMethod, token: "0x06000002" },
          ],
        },
      },
    );

    expect(result.methods).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          status: "unknown",
          match: expect.objectContaining({
            status: "ambiguous",
            basis: "exact-il-signature",
          }),
          limitations: [
            "Multiple managed methods share the same non-name identity key; REA did not guess a token remap.",
          ],
        }),
        expect.objectContaining({
          status: "unknown",
          left: expect.objectContaining({ token: "0x06000002" }),
          limitations: [
            expect.stringMatching(
              /^counterpart-signature-not-decoded: The right method inventory has an unpaired member/u,
            ),
          ],
        }),
      ]),
    );
    expect(result.summary).toMatchObject({ removed: 0, added: 0 });
  });
});

describe("managed member comparison of selected types", () => {
  it("keeps members outside the other side's selection unknown", () => {
    const left = inspect(buildManagedPeFixture(), "/tmp/left-all.dll");
    const right = inspect(buildManagedPeFixture(), "/tmp/right-selected.dll", [
      "Missing.Type",
    ]);
    const result = compareManagedMembers(
      { evidenceId: left.evidenceId, result: left.result },
      { evidenceId: right.evidenceId, result: right.result },
    );

    expect(result.summary).toMatchObject({ added: 0, removed: 0, unknown: 2 });
    expect(result.methods[0]).toMatchObject({
      status: "unknown",
      left: { token: "0x06000001" },
      right: null,
    });
    expect(result.coverage.status).toBe("partial");
    expect(result.limitations).toContain(
      "The observations select different declaring types; a member outside the other side's selection is unknown, not added or removed.",
    );
  });

  it("does not remap members across types neither side observed", () => {
    const left = inspect(buildManagedPeFixture(), "/tmp/left-a.dll", [
      "Fixture.Program",
    ]);
    const right = inspect(
      buildManagedPeFixture({
        mvid: Buffer.from("00112233445566778899aabbccddeefe", "hex"),
        typeName: "A",
        typeNamespace: "X",
      }),
      "/tmp/right-b.dll",
      ["X.A"],
    );
    const result = compareManagedMembers(
      { evidenceId: left.evidenceId, result: left.result },
      { evidenceId: right.evidenceId, result: right.result },
    );

    expect(result.matching.exact_il_signature).toBe(0);
    expect(result.summary).toMatchObject({
      unchanged: 0,
      added: 0,
      removed: 0,
      unknown: 4,
    });
  });

  it("compares two identical selections within those types", () => {
    const left = inspect(buildManagedPeFixture(), "/tmp/left-sel.dll", [
      "Fixture.Program",
    ]);
    const right = inspect(buildManagedPeFixture(), "/tmp/right-sel.dll", [
      "Fixture.Program",
    ]);
    const result = compareManagedMembers(
      { evidenceId: left.evidenceId, result: left.result },
      { evidenceId: right.evidenceId, result: right.result },
    );

    expect(result.methods[0]).toMatchObject({ status: "unchanged" });
    expect(result.coverage.status).toBe("complete-within-inputs");
    expect(result.limitations).toContain(
      "Both observations cover only the selected declaring types (Fixture.Program); member totals and statuses describe those types, not the whole assembly.",
    );
  });
});

describe("managed member comparison of one signature in several types", () => {
  it("pairs a file with itself when two types hold identical members", () => {
    const inspected = withTwin(
      inspect(buildManagedPeFixture(), "/tmp/twin.dll"),
    );
    const result = compareManagedMembers(inspected, inspected);

    expect(result.matching.ambiguous).toBe(0);
    expect(result.summary).toMatchObject({
      unchanged: 4,
      changed: 0,
      added: 0,
      removed: 0,
      unknown: 0,
    });
    for (const item of [...result.methods, ...result.fields])
      expect(item.right?.token).toBe(item.left?.token);
  });

  it.each([1, 2])(
    "keeps a member with its own changed counterpart beside %i identical members of other types",
    (twins) => {
      const left = inspect(buildManagedPeFixture(), "/tmp/own-before.dll");
      const changed = withTwin(
        inspect(
          buildManagedPeFixture({
            ilBody: Buffer.from([
              0x32, 0x02, 0x7b, 0x02, 0x00, 0x00, 0x04, 0x28, 0x02, 0x00, 0x00,
              0x0a, 0x2a,
            ]),
          }),
          "/tmp/own-after.dll",
        ),
        left,
        twins,
      );
      const result = compareManagedMembers(left, changed);

      expect(result.methods).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            status: "changed",
            left: expect.objectContaining({
              declaring_type: "Fixture.Program",
            }),
            right: expect.objectContaining({
              declaring_type: "Fixture.Program",
            }),
            match: expect.objectContaining({ basis: "exact-signature" }),
            dimensions: expect.arrayContaining(["cil"]),
          }),
          expect.objectContaining({
            status: "added",
            right: expect.objectContaining({ declaring_type: "Other.Twin" }),
          }),
        ]),
      );
      expect(result.fields).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            status: "unchanged",
            left: expect.objectContaining({
              declaring_type: "Fixture.Program",
            }),
            right: expect.objectContaining({
              declaring_type: "Fixture.Program",
            }),
          }),
          expect.objectContaining({
            status: "added",
            right: expect.objectContaining({ declaring_type: "Other.Twin" }),
          }),
        ]),
      );
      expect(result.summary).toMatchObject({ unknown: 0, removed: 0 });
    },
  );

  it("does not remap a member whose own identity remains on the other side", () => {
    const left = inspect(buildManagedPeFixture(), "/tmp/sig-before.dll");
    const changed = withTwin(
      inspect(
        buildManagedPeFixture({
          methodSignature: Buffer.from([0x00, 0x00, 0x08]),
          fieldSignature: Buffer.from([0x06, 0x0a]),
        }),
        "/tmp/sig-after.dll",
      ),
      left,
    );
    // Either side may hold the member whose own identity is left behind.
    const forward = compareManagedMembers(left, changed);
    const backward = compareManagedMembers(changed, left);

    for (const item of [
      ...forward.methods,
      ...forward.fields,
      ...backward.methods,
      ...backward.fields,
    ])
      expect(item.match.status).not.toBe("matched");
    expect(forward.summary).toMatchObject({ removed: 2, added: 4 });
    expect(backward.summary).toMatchObject({ removed: 4, added: 2 });
  });

  it("does not remap by structural shape a method whose own identity remains on the other side", () => {
    const left = inspect(buildManagedPeFixture(), "/tmp/shape-before.dll");
    const changed = withTwin(
      inspect(
        buildManagedPeFixture({
          methodSignature: Buffer.from([0x00, 0x00, 0x08]),
        }),
        "/tmp/shape-after.dll",
      ),
      left,
    );
    const [own, twin] = changed.result.methods;
    if (own === undefined || twin === undefined)
      throw new Error("Expected two methods");
    // Same body shape, different CIL digest: only the structural round links
    // the left method to the twin.
    const result = compareManagedMembers(left, {
      ...changed,
      result: {
        ...changed.result,
        methods: [
          own,
          {
            ...twin,
            body: { ...twin.body, normalized_il_sha256: "0".repeat(64) },
          },
        ],
      },
    });

    for (const item of result.methods)
      expect(item.match.status).not.toBe("matched");
  });
});

/**
 * Add copies of the fixture's method and field, each pair declared by another
 * type, to an inspection. The copies come from `source`, so they can carry
 * the bytes of a different build than the inspection they join.
 */
const withTwin = (
  inspected: ReturnType<typeof inspect>,
  source: ReturnType<typeof inspect> = inspected,
  count = 1,
): ReturnType<typeof inspect> => {
  const [method] = source.result.methods;
  const [field] = source.result.fields;
  if (method === undefined || field === undefined)
    throw new Error("Expected a fixture method and field");
  const rows = Array.from({ length: count }, (_, index) => index + 2);
  const twin = (row: number) => ({
    declaring_type: row === 2 ? "Other.Twin" : `Other.Twin${String(row)}`,
    declaring_type_token: `0x0200000${String(row + 1)}`,
  });
  return {
    ...inspected,
    result: {
      ...inspected.result,
      methods: [
        ...inspected.result.methods,
        ...rows.map((row) => ({
          ...method,
          ...twin(row),
          token: `0x0600000${String(row)}`,
        })),
      ],
      fields: [
        ...inspected.result.fields,
        ...rows.map((row) => ({
          ...field,
          ...twin(row),
          token: `0x0400000${String(row)}`,
        })),
      ],
    },
  };
};

const inspect = (bytes: Buffer, path: string, typeNames?: string[]) => {
  const target = managedPeFixtureTarget(bytes, path);
  const result = inspectManagedMembersBytes(
    bytes,
    target,
    typeNames === undefined ? {} : { typeNames },
  );
  return {
    result,
    evidenceId: `ev_${hash(Buffer.from(path))}`,
  };
};

const hash = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");
