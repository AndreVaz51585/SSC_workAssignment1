# Proxy streaming metrics

The proxy defaults to a concise two-line summary when a video response finishes
or aborts. Successful catalog requests are hidden; catalog failures remain visible.
Set `METRICS_FORMAT=detailed` for the exact `event=stream_metrics` records. The four required measurements are encrypted media block count,
decrypted/forwarded block count, observed throughput and processed volume compared
with the original file. No per-block logging is added to the hot path.

## Classes and execution order

Only `src/main/kotlin/ssc/metrics/StreamMetrics.kt` is new. It contains:

- `StreamMetrics`: a mutable accumulator owned by one receiver/connection.
- `StreamMetricsSnapshot`: the immutable final values, `toSummary()` terminal view and
  `toLogLine()` detailed formatter.

`SecureProxyServer.relayResponse()` creates the accumulator and passes it to
`SecureStreamReceiver`. Existing callers can omit it; the default is a fresh
accumulator. The receiver still returns the same Long byte count.

```text
relayResponse creates StreamMetrics
  -> existing connect and handshake
  -> SecureStreamReceiver.receive
       start() before the first record read
       received(frame) after reading a complete frame, before authentication
       metadata(value) after authenticating/decoding metadata
       decrypted(frame, size) after authenticating/validating a DATA block
       forwarded(size) after its browser write and flush succeed
       finish(completed) in finally, on success or failure
  -> relayResponse finally prints the frozen snapshot once
```

No wire format, XML, key derivation, server class or thread model changes are
required. Each concurrent request has its own accumulator; there are no shared
mutable counters. A failed handshake has no receiver sample and keeps the existing
error log. A stream failure is shown once in the summary, including its cause. Catalog and authenticated error responses also collect metrics; detailed mode
logs all of them. Filter
by resource and HTTP status before using logs as video performance results.

## Fields and counting rules

| Field | Meaning |
| --- | --- |
| requestId | Random local log identifier; not a key or protocol/session identifier |
| resource | URL-encoded resource name; decoding restores spaces and Unicode |
| suite / keyBits / mac | Public selected cryptographic profile |
| transfer | `complete` only after valid END, exact body length and successful final output flush; otherwise `aborted` |
| httpStatus | Authenticated origin response status, or `unknown` if no valid metadata |
| originalBytes | Full resource length from authenticated metadata; `unknown` for e.g. 404 |
| expectedBodyBytes | Body length selected for this response (full file, range or error body) |
| rangeStart / rangeEnd | Authenticated selected byte interval for 206, otherwise `none` |
| completeFramesReceived | All complete protocol frames read after the handshake, including a subsequently rejected frame |
| type4FramesReceived | All complete Type 4 frames, including metadata and subsequently rejected frames |
| recordBytesReceived | Sum of 9-byte headers and payload lengths of those complete frames |
| encryptedMediaBlocksReceived | DATA records successfully authenticated, decoded and accepted against the announced length |
| encryptedMediaPayloadBytes | Payload bytes for those DATA records: outer sequence + encrypted subtype/body + tag; excludes 9-byte header |
| decryptedMediaBytes | Accepted plaintext body bytes, including the last block held pending END |
| forwardedMediaBlocks / forwardedMediaBytes | DATA blocks/body bytes whose browser output write AND flush returned successfully |
| elapsedMs | Monotonic elapsed stream-reception time |
| throughputKBps | Forwarded plaintext body bytes / reception seconds / 1000 |

The DATA subtype is encrypted, so untrusted Type 4 frames cannot safely be labeled
as video DATA before authentication. Thus `encryptedMediaBlocksReceived` counts
identified/authenticated DATA, not arbitrary invalid Type 4 input. The two raw
frame counters retain complete rejected-frame information on aborted transfers.
Partial/truncated frame bytes are not included in `recordBytesReceived`. This is
application-record accounting, not a network-interface byte counter: TCP/IP,
retransmissions, handshake Types 1/2/3 and outgoing browser HTTP headers are excluded.

A successful write/flush means the bytes were handed to the socket output; it does
not prove the browser played them. A failed write might already have transferred
some bytes; these metrics deliberately count only fully successful block writes,
so forwarded totals on failure are conservative. The receiver still withholds
its final DATA block until END validates. On abort, decrypted and forwarded totals
can therefore differ without a counter bug.

An authenticated 404/416 with a valid empty body and END has `transfer=complete`:
this describes protocol completion, not successful video playback. Its httpStatus
must be considered separately. An empty successful file has zero DATA blocks.

## Timing methodology

`System.nanoTime()` starts immediately before reading the first stream record,
after the handshake, and stops after the final browser flush or the failing
operation. The interval includes waiting for origin data, record parsing,
authentication/decryption, metadata callback/HTTP header writing and browser
backpressure. It excludes connection establishment, handshake and log formatting.
It measures observed delivery throughput, not isolated cryptographic CPU speed.

```text
throughputKBps = forwardedMediaBytes * 1_000_000 / elapsedNanos
```

kB is decimal (1000 bytes). An interval of zero nanoseconds produces zero rather
than division by zero. Snapshots freeze the duration before logging; output uses
a locale-independent decimal point and URL-encodes textual fields to keep one
physical log line per request.

## Volume and overhead interpretation

For a complete 200 MP4 response:

```text
decryptedMediaBytes = forwardedMediaBytes = expectedBodyBytes = originalBytes
encryptedMediaBlocksReceived = forwardedMediaBlocks
DATA payload bytes = body bytes + DATA blocks * (8 + 1 + tagBytes)
DATA record bytes = DATA payload bytes + DATA blocks * 9
```

The extra byte is the encrypted DATA subtype. Overall `recordBytesReceived` also
includes the protected metadata and END records. Tags are 16 bytes for the permitted
AEAD profiles, or 32/48/64 bytes for HMAC-SHA256/384/512. Therefore protocol volume
is expected to exceed original file size even though these NoPadding modes do not
expand the encrypted plaintext itself.

For 206, compare forwarded bytes to expectedBodyBytes, not originalBytes: a
successful range intentionally transfers only part of the resource. Browser
playback/seek can open several requests, repeat ranges or cancel old requests;
summing every browser response is not the size of one original file. Use a single
full download when measuring full-file overhead, and report concurrency/range
experiments separately. Do not mix aborted and complete transfers in throughput
averages; aggregate complete comparable runs as total bytes / total duration,
and report aborts separately.

## Collect and inspect

After selecting matching private XML files and starting the server, save proxy
stdout while retaining the normal interactive output:

```sh
mkdir -p build
METRICS_FORMAT=detailed build/install/SSC_workAssignment/bin/SSC_workAssignment secure-proxy 8080 localhost 8082 config/profiles/aes256-ctr-hmac-sha256/proxy.config | tee build/proxy.log
```

In another terminal, request one full existing file:

```sh
curl --fail http://localhost:8080/video/sample.mp4 -o build/received.mp4
rg 'event=stream_metrics' build/proxy.log
```

Build/update the launcher first with `./gradlew installDist`. For reliable report
measurements, record the runtime/machine, profile, file size/hash and block size
(current server default: 1024 body bytes), use the same file and setup for all
profiles, distinguish warm-up runs, repeat transfers and record the methodology.
These logs provide observations; manual concurrency and measurement instructions are available in
[performance.md](performance.md).

Tests cover exact accounting, empty streams, partial responses, altered frames,
missing END, browser-output failures, deterministic time/units and safe formatting.
The existing real HTTP suite exercises the instrumentation with all nine profiles
and concurrent requests. Run `./gradlew test` for the complete suite.

## Concise display

The default view keeps the filename, completion/abort, HTTP status, forwarded/expected
body volume, original volume, authenticated/forwarded DATA counts, protocol volume, elapsed time and
MB/s. It omits UUIDs, raw framing counters and repeated cryptographic settings.
Sizes use B/kB/MB as appropriate so small transfers do not appear as 0.00 MB.
Numbers in this human display are rounded; detailed mode retains exact byte counts.
Each two-line summary is passed to println once so concurrent application threads
do not interleave individual summary writes. Docker may prefix each physical line.

`Broken pipe` means a write encountered a closed peer connection. Browsers can
cancel old requests during seeking or video selection; this message alone does not
identify an attack or prove a cryptographic error. The transfer remains marked
INTERROMPIDO. Authentication, sequence and other protocol failures also remain
visible with their cause; they are never converted into successful transfers.

The label is `blocos autenticados/encaminhados`: it counts DATA records, not TCP
packets. With one block pending, a failure writing that previous block after the
next block was authenticated can leave a difference of two (e.g. 4/2). The focused
Kotlin disconnect test verifies four authenticated blocks, two successful writes
and no duplicate output. A completed transfer has matching counts. See the
[worked explanation](performance.md#why-authenticated-and-forwarded-block-counts-can-differ).
