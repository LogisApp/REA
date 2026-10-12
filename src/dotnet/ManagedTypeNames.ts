import type { ManagedParseIssue } from "../domain/managed/managedArtifact.js";
import {
  fullName,
  readCompressed,
  type TypeRange,
} from "./ManagedMemberInspectorCore.js";
import type { ManagedMetadataLayout } from "./ManagedMetadataLayout.js";
import {
  metadataRowCursor,
  metadataToken,
  readMetadataBlob,
  readMetadataString,
} from "./ManagedMetadataHeaps.js";
import { readManagedValue } from "./ManagedReaderFailure.js";

/**
 * Name the type a TypeDef, TypeRef, or generic-instantiation TypeSpec token
 * denotes, in the namespace-qualified form TypeDef `full_name` uses. Other
 * TypeSpec forms and unreadable rows stay null: the type is unknown.
 */
export const typeNameLookup = (
  bytes: Buffer,
  layout: ManagedMetadataLayout,
  ranges: readonly TypeRange[],
  issues: ManagedParseIssue[],
): ((token: string | null) => string | null) => {
  const names = new Map<string, string | null>();
  const resolve = (table: number, row: number): string | null => {
    if (table === 2) return ranges[row - 1]?.fullName ?? null;
    if (table === 1) {
      const cursor = metadataRowCursor(bytes, layout, 1, row);
      cursor.readIndex(layout.codedIndexSize("ResolutionScope"));
      const name = cursor.readIndex(layout.stringIndexSize);
      const namespace = cursor.readIndex(layout.stringIndexSize);
      return fullName(
        readMetadataString(bytes, layout, namespace, layout.strings.size),
        readMetadataString(bytes, layout, name, layout.strings.size),
      );
    }
    if (table !== 27) return null;
    const cursor = metadataRowCursor(bytes, layout, 27, row);
    const spec = readMetadataBlob(
      bytes,
      layout,
      cursor.readIndex(layout.blobIndexSize),
      layout.blob.size,
    );
    // GENERICINST (CLASS | VALUETYPE) TypeDefOrRefOrSpecEncoded ...
    if (spec[0] !== 0x15 || (spec[1] !== 0x12 && spec[1] !== 0x11)) return null;
    const encoded = readCompressed(spec, 2).value;
    const generic = [2, 1, 27][encoded & 3];
    return generic === undefined
      ? null
      : lookup(metadataToken(generic, Math.floor(encoded / 4)));
  };
  const lookup = (token: string | null): string | null => {
    if (token === null) return null;
    if (names.has(token)) return names.get(token) ?? null;
    // Reserve the entry first so a self-referential TypeSpec ends as unknown.
    names.set(token, null);
    const name =
      readManagedValue(
        () =>
          resolve(
            Number.parseInt(token.slice(2, 4), 16),
            Number.parseInt(token.slice(4), 16),
          ),
        issues,
      ) ?? null;
    names.set(token, name);
    return name;
  };
  return lookup;
};
