# Recorded signal decoding

`decode_signal_recording` answers what a selected protocol decoder observes in
an existing recording. It uses caller-supplied **sigrok-cli 0.7.2** with
libsigrokdecode on **Linux**. util-linux `prlimit` is required (default
`/usr/bin/prlimit`, overridable with absolute `REA_SIGROK_PRLIMIT_COMMAND`).
The limiter sets soft and hard address-space limits before the decoder starts.
macOS and Windows are refused because this adapter cannot enforce that limit on
those hosts. It does not acquire samples or communicate with hardware.

```sh
export REA_SIGROK_COMMAND=/absolute/path/to/sigrok-cli
rea decode-signal-recording /artifacts/uart.vcd \
  --decoders uart:rx=RX:baudrate=9600 --input_format vcd \
  --annotations uart=rx-data --format json
```

The corresponding MCP request is:

```json
{
  "name": "decode_signal_recording",
  "arguments": {
    "path": "/artifacts/uart.vcd",
    "decoders": "uart:rx=RX:baudrate=9600",
    "input_format": "vcd",
    "annotations": "uart=rx-data"
  }
}
```

`decoders` uses sigrok's decoder stack and option/channel syntax. Channel names
must match the recording; REA does not guess wiring, baud rate or protocol.
Omitting `input_format` requests sigrok's autodetection. Omitting `annotations`
retains every annotation class. Both omitted selections are recorded as null.
See the [upstream manual](https://sigrok.org/wiki/Sigrok-cli) for formats,
decoder stacking and annotation selectors. No arbitrary command flags are accepted.

The returned Evidence includes the input path/digest, exact selections, tool
configured and resolved paths/digests, full version banner (including library versions), annotation text
with sample-number ranges, and stderr. For example, `1104-1938 uart-1: 52`
is producer display text over a sample range, not a timestamp or an independently
verified protocol fact. Text is retained verbatim; it is not parsed as a lossless
binary payload. Empty output does not establish absence of traffic. Warnings
remain visible even when sigrok exits zero, including `tool.version_diagnostics`
from the separate version probe. Post-run identity failures name the tool, limiter
or private copy involved, rather than blaming the admitted source. Resource-signal
failures retain the signal and effective limits without inferring its exact cause.

REA decodes a private, read-only copy of the recording, verifies that copy and
the selected executable and resource limiter after decoding, and removes the workspace after owned
process cleanup. Failed cleanup retains ownership for retry, and the one-shot
CLI awaits a retry without replacing the original failure or completed Evidence.
Completed observations remain in the MCP session after cancellation or cleanup
failure; bounded post-run integrity checks finish before honoring a late abort. The source file is
never passed to sigrok. Caller-supplied tools and their libraries/decoder modules
are trusted, and hashes identify bytes rather than publisher authenticity.

The input copy is bounded at 32 MiB before reading, each command has a 30-second
deadline, and combined stdout/stderr is bounded at 4 MiB during collection.
Oversized output fails rather than becoming truncated success. These limits do
not form an OS sandbox. Before execution, `prlimit` enforces **1 GiB address
space per process**, **64 MiB per file**, **30 CPU seconds** and no core dumps.
Stricter inherited soft/hard limits are preserved; Evidence records the effective
ceilings. Both limits are set before execution, so decoder allocations and compressed
recording expansion cannot exceed the per-process address-space cap. These are
not aggregate process-memory or filesystem quotas. The selected limiter is
trusted and its path, digest and arguments are retained in Evidence.

## Verification

```sh
npm run build:cached
REA_SIGROK_COMMAND=/absolute/path/to/sigrok-cli node scripts/verify-signal-recording.mjs
```

The verifier synthesizes a 9600-baud 8N1 UART VCD carrying `REA`, then checks
actual CLI/MCP parity, advertised schemas, stored Evidence, source hashes,
annotation filtering/autodetection, invalid decoder/input failures and cleanup.
An optional positional REA entrypoint verifies an installed package.
The real-tool lane requires Linux, sigrok-cli 0.7.2 and libsigrokdecode. A separate
kernel-limit regression checks the inherited soft/hard limits and verifies an
oversized allocation is refused before it can consume memory. Other formats,
decoders and physical acquisition are not established by the UART fixture.
The workflow result must be checked before claiming a specific Linux build
verified. The earlier macOS tool check does not establish the current bounded
integration, which deliberately refuses unsupported hosts.
