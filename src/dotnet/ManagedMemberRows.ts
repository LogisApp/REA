import {
  admitManagedProjection,
  managedDecodeBudget,
  managedJsonStringBytes,
  type ManagedDecodeBudget,
} from "./ManagedDecodeBudget.js";
import type { ManagedPeLayout } from "./ManagedPeReader.js";
import type { ManagedParseIssue } from "../domain/managed/managedArtifact.js";
import type { ManagedMetadataLayout } from "./ManagedMetadataLayout.js";
import {
  signature,
  type ManagedCallEdge,
  type ManagedExportedType,
  type ManagedField,
  type ManagedFieldAccess,
  type ManagedMemberRef,
  type ManagedMethod,
  type MemberCore,
  type TypeRange,
} from "./ManagedMemberInspectorCore.js";
import {
  metadataToken,
  metadataRowCursor,
  metadataCodedToken,
  metadataCodedTokenInvalidReason,
  readMetadataBlob,
  readMetadataString,
} from "./ManagedMetadataHeaps.js";
import { readManagedValue } from "./ManagedReaderFailure.js";
import { methodBody } from "./ManagedMethodBodyReader.js";
import { memberDeclaringTypeRowLookup } from "./ManagedMemberOwnership.js";

/**
 * Declaring-type tokens whose members are decoded in full; null selects every
 * type. Unselected members keep only their name so edges stay labelled.
 */
export type SelectedTypeTokens = ReadonlySet<string> | null;

const isSelected = (
  selected: SelectedTypeTokens,
  declared: { readonly token: string } | undefined,
): boolean =>
  selected === null || (declared !== undefined && selected.has(declared.token));

export const parseFields = (
  bytes: Buffer,
  layout: ManagedMetadataLayout,
  ranges: readonly TypeRange[],
  selected: SelectedTypeTokens = null,
): {
  readonly fields: readonly ManagedField[];
  readonly core: ReadonlyMap<string, MemberCore>;
  readonly issues: readonly ManagedParseIssue[];
} => {
  const fields: ManagedField[] = [];
  const core = new Map<string, MemberCore>();
  const issues: ManagedParseIssue[] = [];
  const table = layout.table(4);
  const ownerRow = readManagedValue(
    () => memberDeclaringTypeRowLookup(bytes, layout, 4),
    issues,
  );
  for (let row = 1; row <= (table?.rowCount ?? 0); row += 1) {
    readManagedValue(() => {
      const cursor = metadataRowCursor(bytes, layout, 4, row);
      const flags = cursor.readUInt16();
      const name = readMetadataString(
        bytes,
        layout,
        cursor.readIndex(layout.stringIndexSize),
        layout.strings.size,
      );
      const owner =
        ownerRow === undefined
          ? 0
          : (readManagedValue(() => ownerRow(row), issues) ?? 0);
      const declared = ranges[owner - 1];
      const token = metadataToken(4, row);
      core.set(token, {
        token,
        name,
        declaringType: declared?.fullName ?? null,
      });
      if (!isSelected(selected, declared)) return;
      const sig = readMetadataBlob(
        bytes,
        layout,
        cursor.readIndex(layout.blobIndexSize),
        layout.blob.size,
      );
      fields.push({
        token,
        row_offset: cursor.start,
        declaring_type_token: declared?.token ?? null,
        declaring_type: declared?.fullName ?? null,
        name,
        flags,
        signature: budgetedSignature(sig, layout),
      });
    }, issues);
  }
  return { fields, core, issues };
};

const TYPE_FORWARDER_FLAG = 0x0020_0000;

/** Read ExportedType rows, including type forwarders, as declared. */
export const parseExportedTypes = (
  bytes: Buffer,
  layout: ManagedMetadataLayout,
): {
  readonly exportedTypes: readonly ManagedExportedType[];
  readonly issues: readonly ManagedParseIssue[];
} => {
  const exportedTypes: ManagedExportedType[] = [];
  const issues: ManagedParseIssue[] = [];
  const table = layout.table(39);
  for (let row = 1; row <= (table?.rowCount ?? 0); row += 1) {
    readManagedValue(() => {
      const cursor = metadataRowCursor(bytes, layout, 39, row);
      const flags = cursor.readUInt32();
      const typeDefId = cursor.readUInt32();
      const name = readMetadataString(
        bytes,
        layout,
        cursor.readIndex(layout.stringIndexSize),
        layout.strings.size,
      );
      const namespace = readMetadataString(
        bytes,
        layout,
        cursor.readIndex(layout.stringIndexSize),
        layout.strings.size,
      );
      const implementationOffset = cursor.offset;
      const implementationRaw = cursor.readIndex(
        layout.codedIndexSize("Implementation"),
      );
      const token = metadataToken(39, row);
      const implementationReason = metadataCodedTokenInvalidReason(
        implementationRaw,
        2,
        [38, 35, 39],
        layout.rowCounts,
      );
      if (implementationReason !== null || implementationRaw === 0)
        issues.push({
          code: "invalid-row",
          scope: `metadata.ExportedType:${token}`,
          offset: implementationOffset,
          detail:
            implementationReason === null
              ? "ExportedType implementation coded index 0x0 is null, but the Implementation column must reference a row"
              : `ExportedType implementation coded index 0x${implementationRaw.toString(16)} is invalid: ${implementationReason}`,
        });
      exportedTypes.push({
        token,
        row_offset: cursor.start,
        namespace,
        name,
        flags,
        forwarder: (flags & TYPE_FORWARDER_FLAG) !== 0,
        type_def_id: typeDefId,
        implementation_token: metadataCodedToken(
          implementationRaw,
          2,
          [38, 35, 39],
          layout.rowCounts,
        ),
      });
    }, issues);
  }
  return { exportedTypes, issues };
};

export const parseMemberRefs = (
  bytes: Buffer,
  layout: ManagedMetadataLayout,
  typeName: (token: string | null) => string | null,
): {
  readonly refs: readonly ManagedMemberRef[];
  readonly core: ReadonlyMap<string, MemberCore>;
  readonly issues: readonly ManagedParseIssue[];
} => {
  const refs: ManagedMemberRef[] = [];
  const core = new Map<string, MemberCore>();
  const issues: ManagedParseIssue[] = [];
  const table = layout.table(10);
  for (let row = 1; row <= (table?.rowCount ?? 0); row += 1) {
    readManagedValue(() => {
      const cursor = metadataRowCursor(bytes, layout, 10, row);
      const parentRaw = cursor.readIndex(
        layout.codedIndexSize("MemberRefParent"),
      );
      const name = readMetadataString(
        bytes,
        layout,
        cursor.readIndex(layout.stringIndexSize),
        layout.strings.size,
      );
      const sig = readMetadataBlob(
        bytes,
        layout,
        cursor.readIndex(layout.blobIndexSize),
        layout.blob.size,
      );
      const token = metadataToken(10, row);
      const parentReason = metadataCodedTokenInvalidReason(
        parentRaw,
        3,
        [2, 1, 26, 6, 27],
        layout.rowCounts,
      );
      if (parentReason !== null || parentRaw === 0)
        issues.push({
          code: "invalid-row",
          scope: `metadata.MemberRef:${token}`,
          offset: cursor.start,
          detail:
            parentReason === null
              ? "MemberRef parent coded index 0x0 is null, but the Class column must reference a row"
              : `MemberRef parent coded index 0x${parentRaw.toString(16)} is invalid: ${parentReason}`,
        });
      const parentToken = metadataCodedToken(
        parentRaw,
        3,
        [2, 1, 26, 6, 27],
        layout.rowCounts,
      );
      const parentName = typeName(parentToken);
      refs.push({
        token,
        row_offset: cursor.start,
        parent_token: parentToken,
        parent_name: parentName,
        name,
        signature: budgetedSignature(sig, layout),
      });
      core.set(token, { token, name, declaringType: parentName });
    }, issues);
  }
  return { refs, core, issues };
};

interface ParseMethodsInput {
  readonly bytes: Buffer;
  readonly layout: ManagedMetadataLayout;
  readonly pe: ManagedPeLayout;
  readonly ranges: readonly TypeRange[];
  readonly selected?: SelectedTypeTokens;
}

export const parseMethods = ({
  bytes,
  layout,
  pe,
  ranges,
  selected = null,
}: ParseMethodsInput): {
  readonly methods: readonly ManagedMethod[];
  readonly core: ReadonlyMap<string, MemberCore>;
  readonly issues: readonly ManagedParseIssue[];
} => {
  const methods: ManagedMethod[] = [];
  const core = new Map<string, MemberCore>();
  const issues: ManagedParseIssue[] = [];
  const table = layout.table(6);
  const ownerRow = readManagedValue(
    () => memberDeclaringTypeRowLookup(bytes, layout, 6),
    issues,
  );
  for (let row = 1; row <= (table?.rowCount ?? 0); row += 1) {
    readManagedValue(() => {
      const cursor = metadataRowCursor(bytes, layout, 6, row);
      const rva = cursor.readUInt32();
      const implFlags = cursor.readUInt16();
      const flags = cursor.readUInt16();
      const name = readMetadataString(
        bytes,
        layout,
        cursor.readIndex(layout.stringIndexSize),
        layout.strings.size,
      );
      const owner =
        ownerRow === undefined
          ? 0
          : (readManagedValue(() => ownerRow(row), issues) ?? 0);
      const declared = ranges[owner - 1];
      const token = metadataToken(6, row);
      core.set(token, {
        token,
        name,
        declaringType: declared?.fullName ?? null,
      });
      if (!isSelected(selected, declared)) return;
      const sig = readMetadataBlob(
        bytes,
        layout,
        cursor.readIndex(layout.blobIndexSize),
        layout.blob.size,
      );
      cursor.readIndex(layout.tableIndexSize(8));
      methods.push({
        token,
        row_offset: cursor.start,
        declaring_type_token: declared?.token ?? null,
        declaring_type: declared?.fullName ?? null,
        name,
        rva,
        impl_flags: implFlags,
        flags,
        signature: budgetedSignature(sig, layout),
        body: methodBody(
          bytes,
          pe,
          rva,
          { implFlags, flags },
          managedDecodeBudget(layout),
        ),
      });
    }, issues);
  }
  return { methods, core, issues };
};

/**
 * Index fields, member references, and methods by token, then name each
 * MethodSpec an inspected body calls after the generic method it instantiates,
 * so every edge target resolves through one lookup.
 */
export const edgeTargets = (
  bytes: Buffer,
  layout: ManagedMetadataLayout,
  methods: readonly ManagedMethod[],
  cores: readonly ReadonlyMap<string, MemberCore>[],
): {
  readonly members: ReadonlyMap<string, MemberCore>;
  readonly issues: readonly ManagedParseIssue[];
} => {
  const members = new Map(cores.flatMap((core) => [...core]));
  const issues: ManagedParseIssue[] = [];
  for (const method of methods)
    for (const { operand } of method.body.anchors) {
      if (operand?.startsWith("0x2b") !== true || members.has(operand))
        continue;
      readManagedValue(() => {
        const cursor = metadataRowCursor(
          bytes,
          layout,
          0x2b,
          Number.parseInt(operand.slice(4), 16),
        );
        const generic = metadataCodedToken(
          cursor.readIndex(layout.codedIndexSize("MethodDefOrRef")),
          1,
          [6, 10],
          layout.rowCounts,
        );
        const target = generic === null ? undefined : members.get(generic);
        if (target !== undefined)
          members.set(operand, { ...target, token: operand });
      }, issues);
    }
  return { members, issues };
};

const TARGET_TABLES = new Map<string, ReadonlySet<string>>([
  ["method", new Set(["0x06", "0x0a", "0x2b"])],
  ["field", new Set(["0x04", "0x0a"])],
]);

const targetKind = (token: string): ManagedCallEdge["target_kind"] =>
  token.startsWith("0x06")
    ? "method-def"
    : token.startsWith("0x0a")
      ? "member-ref"
      : token.startsWith("0x2b")
        ? "method-spec"
        : "unknown";

export const edges = (
  methods: readonly ManagedMethod[],
  members: ReadonlyMap<string, MemberCore>,
  budget: ManagedDecodeBudget,
): {
  readonly callEdges: readonly ManagedCallEdge[];
  readonly fieldAccesses: readonly ManagedFieldAccess[];
} => {
  const callEdges: ManagedCallEdge[] = [];
  const fieldAccesses: ManagedFieldAccess[] = [];
  for (const method of methods) {
    const derives = method.body.anchors.some(
      (anchor) =>
        anchor.opcode !== "ldtoken" &&
        anchor.operand !== null &&
        (anchor.operand_kind === "method" || anchor.operand_kind === "field"),
    );
    if (derives) budget.admitTransient(callerNameBytes(method), null);
    // Built once per method, only after its exact size was admitted.
    const caller = derives ? callerName(method) : method.name;
    for (const anchor of method.body.anchors) {
      if (anchor.opcode === "ldtoken") continue;
      const { operand } = anchor;
      if (operand === null) continue;
      // A token from a table the operand kind cannot name stays unnamed.
      const target = TARGET_TABLES.get(anchor.operand_kind)?.has(
        operand.slice(0, 4),
      )
        ? members.get(operand)
        : undefined;
      if (anchor.operand_kind === "method") {
        // Each derived record is admitted before the graph grows further.
        callEdges.push(
          admitManagedProjection(
            {
              caller_token: method.token,
              caller,
              opcode: anchor.opcode,
              target_token: operand,
              target_kind: targetKind(operand),
              target_name: target?.name ?? null,
              target_declaring_type: target?.declaringType ?? null,
            },
            budget,
          ),
        );
      }
      if (anchor.operand_kind === "field") {
        fieldAccesses.push(
          admitManagedProjection(
            {
              method_token: method.token,
              method: caller,
              opcode: anchor.opcode,
              field_token: operand,
              field_name: target?.name ?? null,
              field_declaring_type: target?.declaringType ?? null,
            },
            budget,
          ),
        );
      }
    }
    // Every record now reserves the name it carries.
    if (derives) budget.releaseTransient();
  }
  return { callEdges, fieldAccesses };
};

const callerName = (method: ManagedMethod): string =>
  method.declaring_type === null
    ? method.name
    : `${method.declaring_type}.${method.name}`;

/** JSON bytes of `callerName`, from its parts: the joining dot adds one byte. */
const callerNameBytes = (method: ManagedMethod): number =>
  method.declaring_type === null
    ? managedJsonStringBytes(method.name)
    : managedJsonStringBytes(method.declaring_type) +
      managedJsonStringBytes(method.name) -
      1;

const budgetedSignature = (
  bytes: Buffer,
  layout: ManagedMetadataLayout,
): ReturnType<typeof signature> => {
  const budget = managedDecodeBudget(layout);
  budget.admitTransient(bytes.length * 256, layout.blob.offset);
  try {
    return admitManagedProjection(
      signature(bytes, budget.digest(bytes, "sha256")),
      budget,
    );
  } finally {
    budget.releaseTransient();
  }
};
