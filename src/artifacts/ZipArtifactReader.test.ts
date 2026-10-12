import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { TextReader, Uint8ArrayWriter, ZipWriter } from "@zip.js/zip.js";
import { describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";

import { ZipArtifactReader } from "./ZipArtifactReader.js";
import {
  ARTIFACT_DECOMPRESSION_RATIO,
  artifactDecompressionBudgetBytes,
  MINIMUM_ARTIFACT_DECOMPRESSION_BYTES,
} from "../domain/artifactDecompressionBudget.js";

/** Write one real ZIP entry, then forge its central-directory uncompressed size. */
const writeZipWithDeclaredSize = async (
  directory: string,
  declaredBytes: number,
): Promise<string> => {
  const path = join(directory, "fixture.zip");
  const writer = new ZipWriter(new Uint8ArrayWriter());
  await writer.add("member.bin", new TextReader("real member bytes"));
  await writeFile(path, await writer.close());
  const bytes = await readFile(path);
  const centralDirectory = bytes.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
  if (centralDirectory < 0) throw new Error("Expected a ZIP central directory");
  // The uncompressed size is the u32 at offset 24 of the central-directory record.
  bytes.writeUInt32LE(declaredBytes, centralDirectory + 24);
  await writeFile(path, bytes);
  return path;
};

const enumerate = async (reader: ZipArtifactReader): Promise<number> => {
  let files = 0;
  for await (const entry of reader.entries())
    if (entry.kind === "file") files += 1;
  return files;
};

describe("ZipArtifactReader decompression budget", () => {
  it("refuses an archive whose entries declare more than its size can justify", async () => {
    const directory = await createTestTempDirectory("rea-zip-budget-bomb-");
    // A ~160-byte archive cannot declare 2 GiB of members without being a bomb.
    const path = await writeZipWithDeclaredSize(directory, 2_147_483_647);
    const reader = new ZipArtifactReader(path, "zip");
    try {
      await expect(enumerate(reader)).rejects.toMatchObject({
        name: "ArtifactReaderFailure",
        reason: "limit",
      });
    } finally {
      await reader.close();
    }
  });

  it("still enumerates an archive within its decompression budget", async () => {
    const directory = await createTestTempDirectory("rea-zip-budget-ok-");
    const path = await writeZipWithDeclaredSize(directory, 64 * 1024 * 1024);
    const reader = new ZipArtifactReader(path, "zip");
    try {
      expect(await enumerate(reader)).toBe(1);
    } finally {
      await reader.close();
    }
  });

  it("scales the budget with the archive so large packages stay usable", async () => {
    const directory = await createTestTempDirectory("rea-zip-budget-scale-");
    const path = await writeZipWithDeclaredSize(directory, 1024);
    const reader = new ZipArtifactReader(path, "zip");
    try {
      // A 1 KiB archive is granted the floor, not the floor divided by its size.
      expect(await enumerate(reader)).toBe(1);
    } finally {
      await reader.close();
    }
  });
});

describe("artifactDecompressionBudgetBytes", () => {
  it("grants at least the floor and grows with the compressed size", () => {
    expect(artifactDecompressionBudgetBytes(0)).toBe(
      MINIMUM_ARTIFACT_DECOMPRESSION_BYTES,
    );
    expect(artifactDecompressionBudgetBytes(1024)).toBe(
      MINIMUM_ARTIFACT_DECOMPRESSION_BYTES,
    );
    const large = MINIMUM_ARTIFACT_DECOMPRESSION_BYTES * 4;
    expect(artifactDecompressionBudgetBytes(large)).toBe(
      large * ARTIFACT_DECOMPRESSION_RATIO,
    );
  });
});
