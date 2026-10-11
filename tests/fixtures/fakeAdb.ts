import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { onTestFinished } from "vitest";

/** A POSIX shell adb stub and the private directory that owns it. */
export interface FakeAdb {
  readonly binary: string;
  readonly root: string;
  /** Appended to once per `adb pull`; absent when nothing was pulled. */
  readonly pullLog: string;
}

/**
 * Write an adb stub whose `pm path` prints each raw device path as one
 * `package:` line and whose `pull` records the call and writes a stub APK.
 */
export const writeFakeAdbPmPath = async (
  devicePaths: readonly string[],
): Promise<FakeAdb> => {
  const root = await mkdtemp(join(tmpdir(), "rea-fake-adb-"));
  onTestFinished(() => rm(root, { recursive: true, force: true }));
  const binary = join(root, "adb");
  const pullLog = join(root, "pull.log");
  const quoted = devicePaths
    .map((path) => `'package:${path.replaceAll("'", "'\\''")}'`)
    .join(" ");
  await writeFile(
    binary,
    `#!/bin/sh
if [ "$1" = "version" ]; then
  printf 'Android Debug Bridge version 1.0.41\\nVersion 34.0.5-stub\\nInstalled as %s\\n' "$0"
  exit 0
fi
if [ "$1" = "-s" ] && [ "$4" = "pm" ] && [ "$5" = "path" ]; then
  printf '%s\\n' ${quoted}
  exit 0
fi
if [ "$1" = "-s" ] && [ "$3" = "pull" ]; then
  printf 'pulled\\n' >> '${pullLog}'
  printf 'x' > "$5"
  exit 0
fi
printf 'unexpected arguments: %s\\n' "$@" >&2
exit 1
`,
    { mode: 0o755 },
  );
  return { binary, root, pullLog };
};
