import type { FileHandle } from "node:fs/promises";
import type { ArmElfMetadata } from "../domain/binaryTargetTypes.js";
import { err, ok, type Result } from "../domain/result.js";

/** Observed AEABI declarations and coverage of their source tables. */
export interface ArmElfAttributesInspection {
  readonly cpuArch: number | null;
  readonly cpuArchProfile: string | null;
  readonly limitations: readonly string[];
}

/** File-scope AEABI declarations; other scopes do not declare the ISA. */
interface AeabiFileDeclarations {
  readonly cpuArch: number | null;
  readonly cpuArchProfile: string | null;
}

const NO_AEABI_DECLARATIONS: AeabiFileDeclarations = {
  cpuArch: null,
  cpuArchProfile: null,
};

/** SHT_ARM_ATTRIBUTES carries the AEABI declarations for an ELF32 ARM image. */
const SHT_ARM_ATTRIBUTES = 0x70000003;
const ARM_ATTRIBUTES_MAX_BYTES = 65536;
const ARM_ATTRIBUTES_MAX_TAGS = 4096;
/** Tag_CPU_arch (6) and Tag_CPU_arch_profile (7), a one-byte character. */
const TAG_CPU_ARCH = 6;
const TAG_CPU_ARCH_PROFILE = 7;

/** Read one ULEB128 value; null on truncation or an over-long encoding. */
const readUleb128 = (
  bytes: Buffer,
  start: number,
  end: number,
): { value: number; next: number } | null => {
  let value = 0;
  let shift = 0;
  let cursor = start;
  while (cursor < end && shift <= 28) {
    const byte = bytes[cursor];
    if (byte === undefined) return null;
    cursor += 1;
    value += (byte & 0x7f) * 2 ** shift;
    if ((byte & 0x80) === 0) return { value, next: cursor };
    shift += 7;
  }
  return null;
};

const skipAttributesString = (
  bytes: Buffer,
  start: number,
  end: number,
): number | null => {
  const terminator = bytes.indexOf(0, start);
  return terminator < 0 || terminator >= end ? null : terminator + 1;
};

/**
 * Scan one File scope's tag/value pairs for Tag_CPU_arch (6) and
 * Tag_CPU_arch_profile (7). Scope tags cannot nest, Tag_NULL carries no
 * value, tags 4, 5, and 32 carry strings, and every other declared tag
 * carries one ULEB value; malformed shapes read back as no declaration.
 */
const scanAeabiFileScope = (
  section: Buffer,
  start: number,
  end: number,
): AeabiFileDeclarations | null => {
  let cursor = start;
  let cpuArch: number | null = null;
  let cpuArchProfile: string | null = null;
  let tags = 0;
  while (cursor < end) {
    if ((tags += 1) > ARM_ATTRIBUTES_MAX_TAGS) return null;
    const tag = readUleb128(section, cursor, end);
    if (tag === null) return null;
    cursor = tag.next;
    if (tag.value === TAG_CPU_ARCH || tag.value === TAG_CPU_ARCH_PROFILE) {
      const value = readUleb128(section, cursor, end);
      if (value === null) return null;
      cursor = value.next;
      if (tag.value === TAG_CPU_ARCH) cpuArch = value.value;
      else if (value.value < 1 || value.value > 127) return null;
      else cpuArchProfile = String.fromCharCode(value.value);
      continue;
    }
    if (tag.value === 0) continue;
    if (tag.value >= 1 && tag.value <= 3) return null;
    if (tag.value === 4 || tag.value === 5) {
      const next = skipAttributesString(section, cursor, end);
      if (next === null) return null;
      cursor = next;
      continue;
    }
    if (tag.value === 32) {
      const compatibility = readUleb128(section, cursor, end);
      if (compatibility === null) return null;
      const next = skipAttributesString(section, compatibility.next, end);
      if (next === null) return null;
      cursor = next;
      continue;
    }
    const value = readUleb128(section, cursor, end);
    if (value === null) return null;
    cursor = value.next;
  }
  return { cpuArch, cpuArchProfile };
};

/**
 * Walk one aeabi subsection's length-delimited scope blocks. Only File
 * scopes declare the architecture; Section and Symbol scopes are skipped
 * whole, so their bytes can never read as a CPU_arch declaration, and a
 * later File scope supersedes an earlier one as sequential consumers do.
 */
const aeabiDeclarations = (
  section: Buffer,
  start: number,
  end: number,
): AeabiFileDeclarations | null => {
  let cursor = start;
  let declarations: AeabiFileDeclarations = NO_AEABI_DECLARATIONS;
  while (cursor < end) {
    const scope = readUleb128(section, cursor, end);
    if (scope === null || scope.value < 1 || scope.value > 3) return null;
    if (scope.next + 4 > end) return null;
    const blockEnd = cursor + section.readUInt32LE(scope.next);
    if (blockEnd < scope.next + 4 || blockEnd > end) return null;
    if (scope.value === 1) {
      const scanned = scanAeabiFileScope(section, scope.next + 4, blockEnd);
      if (scanned === null) return null;
      declarations = scanned;
    }
    cursor = blockEnd;
  }
  return declarations;
};

/**
 * Parse an AEABI attributes payload: 'A', then subsections of a 4-byte
 * length, a NUL-terminated owner, and length-delimited scope blocks. Only
 * the public aeabi subsection declares the architecture; other owners and
 * every malformed shape read back as no declaration.
 */
const armAttributesDeclarations = (section: Buffer): AeabiFileDeclarations => {
  if (section.length < 2 || section[0] !== 0x41) return NO_AEABI_DECLARATIONS;
  let cursor = 1;
  while (cursor + 4 <= section.length) {
    const subsectionEnd = cursor + section.readUInt32LE(cursor);
    if (
      subsectionEnd <= cursor + 4 ||
      subsectionEnd > section.length ||
      subsectionEnd > cursor + ARM_ATTRIBUTES_MAX_BYTES
    )
      return NO_AEABI_DECLARATIONS;
    const ownerEnd = skipAttributesString(section, cursor + 4, subsectionEnd);
    if (ownerEnd === null) return NO_AEABI_DECLARATIONS;
    const owner = section.toString("ascii", cursor + 4, ownerEnd - 1);
    if (owner === "aeabi") {
      const declarations = aeabiDeclarations(section, ownerEnd, subsectionEnd);
      return declarations === null ? NO_AEABI_DECLARATIONS : declarations;
    }
    cursor = subsectionEnd;
  }
  return NO_AEABI_DECLARATIONS;
};

/**
 * Read Tag_CPU_arch from .ARM.attributes of the caller's already-open ELF32
 * ARM file, including sections beyond the initial header probe. A missing
 * declaration is unknown, not a default architecture; the ELF header cannot
 * establish the CPU ISA. The caller supplies its cancellation check so its
 * tagged error is preserved.
 */
export const readArmElfCpuArch = async (
  handle: FileHandle,
  metadata: ArmElfMetadata,
  checkCancelled: () => void,
): Promise<Result<ArmElfAttributesInspection, string>> => {
  checkCancelled();
  if (metadata.elfClass !== 32)
    return err("ARM attribute inspection currently supports ELF32 only");
  const fileSize = (await handle.stat()).size;
  checkCancelled();
  const read = async (
    offset: number,
    length: number,
    label: string,
  ): Promise<Result<Buffer, string>> => {
    checkCancelled();
    if (
      !Number.isSafeInteger(fileSize) ||
      offset < 0 ||
      length < 0 ||
      offset > fileSize - length
    )
      return err(`ARM ${label} lies outside the file`);
    const bytes = Buffer.alloc(length);
    let total = 0;
    while (total < length) {
      checkCancelled();
      const observed = await handle.read(
        bytes,
        total,
        length - total,
        offset + total,
      );
      checkCancelled();
      if (observed.bytesRead === 0) return err(`truncated ARM ${label}`);
      total += observed.bytesRead;
    }
    return ok(bytes);
  };
  const header = await read(0, 52, "ELF32 header");
  if (!header.ok) return header;
  const bytes = header.value;
  const little = metadata.byteOrder === "little";
  const u16 = (data: Buffer, offset: number): number =>
    little ? data.readUInt16LE(offset) : data.readUInt16BE(offset);
  const u32 = (data: Buffer, offset: number): number =>
    little ? data.readUInt32LE(offset) : data.readUInt32BE(offset);
  if (
    bytes.toString("hex", 0, 4) !== "7f454c46" ||
    bytes[4] !== 1 ||
    bytes[5] !== (little ? 1 : 2) ||
    u16(bytes, 18) !== 40 ||
    u16(bytes, 16) !== metadata.type ||
    u32(bytes, 36) !== metadata.flags
  )
    return err("ARM ELF header no longer matches the resolved identity");
  if (bytes[6] !== 1 || u32(bytes, 20) !== 1 || u16(bytes, 40) !== 52)
    return err("invalid ARM ELF32 version or header size");
  // Extended numbering needs a separate section-zero reader. Refuse it rather
  // than silently treating an unexamined table as having no declarations.
  if (u16(bytes, 48) >= 0xff00)
    return err("extended or reserved ARM ELF table numbering is unsupported");
  const tableOffset = u32(bytes, 32);
  const count = u16(bytes, 48);
  const stride = u16(bytes, 46);
  const limitations: string[] = [];
  if (count === 0) {
    if (tableOffset !== 0)
      return err("unsupported extended or inconsistent ARM section table");
    return ok({ cpuArch: null, cpuArchProfile: null, limitations });
  }
  // The exact ELF32 entry size bounds the table allocation by the header
  // count alone; a padded stride could multiply a sparse file into one.
  if (tableOffset < 52 || stride !== 40)
    return err("invalid ARM section table offset or entry size");
  const examinable = Math.min(
    count,
    Math.max(0, Math.floor((fileSize - tableOffset) / stride)),
  );
  if (examinable < count)
    limitations.push(
      `ARM section header table at file offset ${tableOffset} extends beyond the captured file: examined ${examinable} of ${count} complete headers. Declarations in unavailable headers remain unknown.`,
    );
  if (examinable === 0)
    return ok({ cpuArch: null, cpuArchProfile: null, limitations });
  const contents = await read(
    tableOffset,
    examinable * stride,
    "section header table",
  );
  if (!contents.ok) return contents;
  const locateAttributesSection = async (): Promise<
    Result<Buffer | undefined, string>
  > => {
    let section: Buffer | undefined;
    for (let index = 0; index < examinable; index += 1) {
      checkCancelled();
      const position = index * stride;
      if (u32(contents.value, position + 4) !== SHT_ARM_ATTRIBUTES) continue;
      if (section !== undefined)
        return err("duplicate ARM attribute sections in the section table");
      const offset = u32(contents.value, position + 16);
      const size = u32(contents.value, position + 20);
      if (size <= 0 || size > ARM_ATTRIBUTES_MAX_BYTES)
        return err("unsupported ARM attribute section size");
      const candidate = await read(offset, size, "attribute section");
      if (!candidate.ok) return candidate;
      section = candidate.value;
    }
    return ok(section);
  };
  const section = await locateAttributesSection();
  if (!section.ok) return section;
  if (section.value === undefined)
    return ok({ cpuArch: null, cpuArchProfile: null, limitations });
  // Preserve the declarations verbatim, including unknown enum values.
  // Provider admission, not parsing, decides which ISAs have been verified.
  return ok({
    ...armAttributesDeclarations(section.value),
    limitations,
  });
};
