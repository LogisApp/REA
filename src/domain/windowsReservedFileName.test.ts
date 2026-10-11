import { describe, expect, it } from "vitest";

import { isWindowsReservedFileName } from "./windowsReservedFileName.js";

describe("isWindowsReservedFileName", () => {
  it.each(["CON", "nul", "Aux", "PRN.txt", "com1.apk", "LPT9.tar.gz"])(
    "treats %s as a reserved device name",
    (segment) => {
      expect(isWindowsReservedFileName(segment)).toBe(true);
    },
  );

  it.each(["console", "nullable.apk", "com10", "lpt0.apk", "base.apk", "xnul"])(
    "accepts %s",
    (segment) => {
      expect(isWindowsReservedFileName(segment)).toBe(false);
    },
  );
});
