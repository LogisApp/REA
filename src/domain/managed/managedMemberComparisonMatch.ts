import { createHash } from "node:crypto";

import canonicalize from "canonicalize";

import {
  managedMemberInspectionSchema,
  type ManagedMemberInspection,
} from "./managedArtifact.js";
import { parseManagedInspectionEvidence } from "./managedInspectionEvidence.js";
import type {
  ManagedMemberComparisonResult,
  ManagedMemberComparisonSide,
} from "./managedMemberComparison.js";
import type { JsonValue } from "../jsonValue.js";

export const sha256 = (value: JsonValue): string => {
  const serialized = canonicalize(value);
  if (serialized === undefined)
    throw new TypeError("Managed comparison canonicalization failed");
  return createHash("sha256").update(serialized).digest("hex");
};

type Method = ManagedMemberInspection["methods"][number];
type Field = ManagedMemberInspection["fields"][number];
type MatchBasis =
  ManagedMemberComparisonResult["methods"][number]["match"]["basis"];
type ConcreteMatchBasis = Exclude<MatchBasis, "none">;

interface Keyed<Item> {
  readonly item: Item;
  readonly exactKey: string | null;
  readonly signatureKey: string | null;
  readonly structuralKey: string | null;
}

interface MatchedPair<Item> {
  readonly left: Keyed<Item>;
  readonly right: Keyed<Item>;
  readonly basis: ConcreteMatchBasis;
  readonly confidence: "exact" | "high";
}

interface Ambiguous<Item> {
  readonly left: readonly Keyed<Item>[];
  readonly right: readonly Keyed<Item>[];
  readonly basis: ConcreteMatchBasis;
}

const keyMethod = (item: Method): Keyed<Method> => ({
  item,
  exactKey:
    item.body.status === "present" && item.body.normalized_il_sha256 !== null
      ? sha256([
          "method-exact",
          item.signature.raw_sha256,
          item.body.normalized_il_sha256,
        ])
      : null,
  // The raw blob is the exact signature; decoding only feeds shape keys.
  signatureKey: sha256([
    "method-signature",
    item.declaring_type,
    item.name,
    item.signature.raw_sha256,
  ]),
  structuralKey:
    item.signature.parse_status === "decoded" && item.body.status === "present"
      ? sha256([
          "method-structural",
          item.signature.kind,
          item.signature.calling_convention,
          item.signature.generic_parameter_count,
          item.signature.parameter_count,
          item.signature.return_type,
          item.signature.parameter_types,
          item.body.status,
          item.body.header_format,
          item.body.il_size,
          item.body.max_stack,
          item.body.init_locals,
          item.body.opcode_counts,
          item.body.anchors.map(({ opcode, operand_kind }) => [
            opcode,
            operand_kind,
          ]),
          item.body.exception_regions.map((region) => [
            region.flags,
            region.try_length,
            region.handler_length,
            region.class_token === null ? null : "type-token",
            region.filter_offset === null ? null : "filter",
          ]),
        ])
      : null,
});

const keyField = (item: Field): Keyed<Field> => ({
  item,
  exactKey:
    item.signature.parse_status === "decoded"
      ? sha256(["field-exact", item.signature.raw_sha256])
      : null,
  // Only an undecoded field reaches this round: a decoded field with the
  // same raw signature already met its counterpart in the exact round.
  signatureKey: sha256([
    "field-signature",
    item.declaring_type,
    item.name,
    item.signature.raw_sha256,
  ]),
  structuralKey: sha256([
    "field-structural",
    item.signature.kind,
    item.signature.field_type,
    item.flags,
  ]),
});

const matchMethods = (
  left: readonly Keyed<Method>[],
  right: readonly Keyed<Method>[],
) =>
  matchByKeys({
    left,
    right,
    rounds: [
      {
        basis: "exact-il-signature",
        key: declaredAs(({ exactKey }) => exactKey),
      },
      {
        basis: "exact-signature",
        key: ({ signatureKey }) => signatureKey,
      },
      {
        basis: "exact-il-signature",
        key: ({ exactKey }) => exactKey,
        remap: true,
      },
      {
        basis: "structural-method-shape",
        key: ({ structuralKey }) => structuralKey,
        remap: true,
      },
    ],
  });

const matchFields = (
  left: readonly Keyed<Field>[],
  right: readonly Keyed<Field>[],
) =>
  matchByKeys({
    left,
    right,
    rounds: [
      {
        basis: "field-signature",
        key: declaredAs(({ exactKey }) => exactKey),
      },
      {
        basis: "exact-signature",
        key: ({ signatureKey }) => signatureKey,
      },
      {
        basis: "field-signature",
        key: ({ exactKey }) => exactKey,
        remap: true,
      },
    ],
  });

export type ManagedMethodMatches = ReturnType<typeof matchMethods>;
export type ManagedFieldMatches = ReturnType<typeof matchFields>;

interface Member {
  readonly declaring_type: string | null;
  readonly name: string;
}

interface MatchRound<Item> {
  readonly basis: ConcreteMatchBasis;
  readonly key: (item: Keyed<Item>) => string | null;
  /**
   * The key omits the declared type and name, so a pair may join different
   * declared identities. Such a remap is skipped when either member's own
   * identity is still unpaired on the other side.
   */
  readonly remap?: true;
}

interface MatchByKeysInput<Item> {
  readonly left: readonly Keyed<Item>[];
  readonly right: readonly Keyed<Item>[];
  readonly rounds: readonly MatchRound<Item>[];
}

const identityOf = ({ declaring_type, name }: Member): string =>
  sha256([declaring_type, name]);

/** Narrow a key to members of one declared type and name. */
const declaredAs =
  <Item extends Member>(key: (item: Keyed<Item>) => string | null) =>
  (item: Keyed<Item>): string | null => {
    const value = key(item);
    return value === null ? null : sha256([identityOf(item.item), value]);
  };

const matchByKeys = <Item extends Member>({
  left,
  right,
  rounds,
}: MatchByKeysInput<Item>): {
  readonly pairs: readonly MatchedPair<Item>[];
  readonly ambiguous: readonly Ambiguous<Item>[];
  readonly leftOnly: readonly Keyed<Item>[];
  readonly rightOnly: readonly Keyed<Item>[];
} => {
  const usedLeft = new Set<Keyed<Item>>();
  const usedRight = new Set<Keyed<Item>>();
  const pairs: MatchedPair<Item>[] = [];
  const ambiguous: Ambiguous<Item>[] = [];
  for (const round of rounds) {
    const leftGroups = groupBy(
      left.filter((item) => !usedLeft.has(item)),
      round.key,
    );
    const rightGroups = groupBy(
      right.filter((item) => !usedRight.has(item)),
      round.key,
    );
    // Identities still unpaired as the round starts, so remaps within one
    // round do not depend on the order in which their groups are visited.
    const open =
      round.remap === true
        ? { left: unpaired(left, usedLeft), right: unpaired(right, usedRight) }
        : null;
    for (const [key, leftItems] of leftGroups) {
      const rightItems = rightGroups.get(key);
      if (rightItems === undefined) continue;
      if (leftItems.length === 1 && rightItems.length === 1) {
        const [leftItem] = leftItems;
        const [rightItem] = rightItems;
        if (leftItem === undefined || rightItem === undefined) continue;
        if (
          open !== null &&
          identityOf(leftItem.item) !== identityOf(rightItem.item) &&
          (open.right.has(identityOf(leftItem.item)) ||
            open.left.has(identityOf(rightItem.item)))
        )
          continue;
        usedLeft.add(leftItem);
        usedRight.add(rightItem);
        pairs.push({
          left: leftItem,
          right: rightItem,
          basis: round.basis,
          confidence:
            round.basis === "exact-il-signature" ||
            round.basis === "exact-signature" ||
            round.basis === "field-signature"
              ? "exact"
              : "high",
        });
      } else {
        for (const item of leftItems) usedLeft.add(item);
        for (const item of rightItems) usedRight.add(item);
        ambiguous.push({
          left: leftItems,
          right: rightItems,
          basis: round.basis,
        });
      }
    }
  }
  return {
    pairs,
    ambiguous,
    leftOnly: left.filter((item) => !usedLeft.has(item)),
    rightOnly: right.filter((item) => !usedRight.has(item)),
  };
};

/** Declared identities of the members no earlier pair or group has taken. */
const unpaired = <Item extends Member>(
  items: readonly Keyed<Item>[],
  used: ReadonlySet<Keyed<Item>>,
): ReadonlySet<string> =>
  new Set(
    items.filter((item) => !used.has(item)).map(({ item }) => identityOf(item)),
  );

const groupBy = <Item>(
  items: readonly Item[],
  keyOf: (item: Item) => string | null,
): Map<string, readonly Item[]> => {
  const grouped = new Map<string, Item[]>();
  for (const item of items) {
    const key = keyOf(item);
    if (key === null) continue;
    const bucket = grouped.get(key) ?? [];
    bucket.push(item);
    grouped.set(key, bucket);
  }
  return grouped;
};

/** Whether a side's inventory observed members of this declaring type. */
const observedBy =
  (side: ManagedMemberComparisonSide) =>
  ({ declaring_type }: { readonly declaring_type: string | null }): boolean =>
    side.result.selection === null ||
    (declaring_type !== null &&
      side.result.selection.type_names.includes(declaring_type));

/**
 * Pair only members whose declaring type both sides observed. A member outside
 * the other side's selection stays one-sided, so a type selection never yields
 * a remap to a member of a type the other side did not inspect.
 */
const matchObserved = <Item extends Member>(
  left: readonly Item[],
  right: readonly Item[],
  sides: {
    readonly inLeft: (item: Item) => boolean;
    readonly inRight: (item: Item) => boolean;
  },
  match: (
    left: readonly Keyed<Item>[],
    right: readonly Keyed<Item>[],
  ) => ReturnType<typeof matchByKeys<Item>>,
  key: (item: Item) => Keyed<Item>,
): ReturnType<typeof matchByKeys<Item>> => {
  const matched = match(
    left.filter(sides.inRight).map(key),
    right.filter(sides.inLeft).map(key),
  );
  return {
    ...matched,
    leftOnly: [
      ...matched.leftOnly,
      ...left.filter((item) => !sides.inRight(item)).map(key),
    ],
    rightOnly: [
      ...matched.rightOnly,
      ...right.filter((item) => !sides.inLeft(item)).map(key),
    ],
  };
};

export const keyMembers = (
  left: ManagedMemberComparisonSide,
  right: ManagedMemberComparisonSide,
): {
  readonly methodMatches: ReturnType<typeof matchMethods>;
  readonly fieldMatches: ReturnType<typeof matchFields>;
} => {
  const sides = { inLeft: observedBy(left), inRight: observedBy(right) };
  return {
    methodMatches: matchObserved(
      left.result.methods,
      right.result.methods,
      sides,
      matchMethods,
      keyMethod,
    ),
    fieldMatches: matchObserved(
      left.result.fields,
      right.result.fields,
      sides,
      matchFields,
      keyField,
    ),
  };
};

export const parseManagedMemberEvidence = (
  evidence: unknown,
): {
  readonly evidenceId: string;
  readonly result: ManagedMemberInspection;
} => {
  const parsed = parseManagedInspectionEvidence(
    evidence,
    "inspect_managed_members",
    managedMemberInspectionSchema,
  );
  return {
    evidenceId: parsed.evidence.evidence_id,
    result: parsed.result,
  };
};
