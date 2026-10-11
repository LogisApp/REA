/**
 * Win32 reserved device names. Windows resolves these basenames to a device
 * regardless of case and of any extension (`NUL.apk`, `con.tar.gz`), so a
 * portable host file name must avoid them on every host, not only on Windows.
 */
const WINDOWS_RESERVED_BASENAME =
  /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/iu;

/** Whether one path segment names a Win32 reserved device, with or without an extension. */
export const isWindowsReservedFileName = (segment: string): boolean =>
  WINDOWS_RESERVED_BASENAME.test(segment);
