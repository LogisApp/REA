import { lstat } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";

import { writeFakeAdbPmPath } from "../../fixtures/fakeAdb.js";
import { serveCli as serve } from "./cliServeHarness.js";

it.each([
  ["inspect-adb-client"],
  ["list-adb-devices"],
  ["inspect-adb-device"],
  ["list-adb-packages"],
  ["pull-adb-package"],
  ["read-adb-logcat"],
  ["inspect-adb-package"],
  ["pull-adb-file"],
  ["push-adb-file"],
  ["capture-adb-screen"],
  ["list-adb-processes"],
  ["list-adb-directory"],
  ["list-adb-features"],
  ["list-adb-services"],
  ["inspect-adb-display"],
  ["inspect-adb-window"],
  ["read-adb-setting"],
  ["collect-adb-bugreport"],
  ["resolve-adb-packages"],
  ["install-adb-package"],
  ["uninstall-adb-package"],
  ["start-adb-app"],
  ["start-adb-activity"],
  ["stop-adb-app"],
])("%s advertises a schema through the public CLI", async (command) => {
  const result = await serve([command, "--schema", "--json"]);
  expect(result.exitCode, command).toBe(0);
  const schema = JSON.parse(result.stdout) as { args?: unknown };
  expect(schema).toBeTruthy();
});

it("reports a missing adb binary with recovery guidance", async () => {
  const result = await serve(["inspect-adb-client", "--json"], {
    REA_ADB_PATH: "/nonexistent/adb",
  });
  expect(result.stdout).toContain("capability_unavailable");
  expect(result.stdout).toContain("REA_ADB_PATH");
});

it("validates device serials before contacting any device", async () => {
  const result = await serve(["inspect-adb-device", "bad serial", "--json"]);
  expect(result.stdout).toContain("invalid_input");
});

it("requires the output directory option on pull", async () => {
  const result = await serve([
    "pull-adb-package",
    "emulator-5554",
    "com.example",
    "--json",
  ]);
  expect(result.exitCode).not.toBe(0);
});

const posixIt = it.skipIf(process.platform === "win32");

const pullHostilePackage = async (devicePaths: readonly string[]) => {
  const adb = await writeFakeAdbPmPath(devicePaths);
  const output = join(adb.root, "pulls");
  const result = await serve(
    [
      "pull-adb-package",
      "emulator-5554",
      "com.hostile",
      "--output-directory",
      output,
      "--json",
    ],
    { REA_ADB_PATH: adb.binary },
  );
  await expect(lstat(adb.pullLog)).rejects.toThrow(/ENOENT/u);
  await expect(lstat(output)).rejects.toThrow(/ENOENT/u);
  return JSON.parse(result.stdout) as Record<string, unknown>;
};

posixIt(
  "projects the unsafe pm path entry and its reason to CLI callers",
  async () => {
    const hostile = "/data/\u202eppa/x/base.apk";
    const projected = await pullHostilePackage([
      "/data/app/x/base.apk",
      hostile,
    ]);
    expect(projected).toMatchObject({
      code: "unreadable_output",
      retryable: false,
      details: {
        operation: "pull_adb_package",
        reason: "unsafe_device_path",
        diagnostics: {
          package_name: "com.hostile",
          rejected_paths: [
            {
              device_path: hostile,
              file_name: "base.apk",
              reason: "whitespace_or_control",
            },
          ],
        },
        captured_output: {
          stdout: expect.stringContaining(hostile) as unknown,
        },
      },
    });
    expect(projected.message).toContain("\\u{202E}");
    expect(projected.message).not.toContain("rea doctor");
  },
);

posixIt(
  "projects both case-folded pm path entries to CLI callers",
  async () => {
    const projected = await pullHostilePackage([
      "/data/app/x/base.apk",
      "/data/app/y/BASE.apk",
    ]);
    expect(projected).toMatchObject({
      code: "unreadable_output",
      details: {
        reason: "aliased_device_paths",
        diagnostics: {
          alias_reason: "case_fold_alias",
          aliased_paths: [
            { device_path: "/data/app/x/base.apk", file_name: "base.apk" },
            { device_path: "/data/app/y/BASE.apk", file_name: "BASE.apk" },
          ],
        },
      },
    });
  },
);
