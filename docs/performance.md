# Manual concurrency and throughput validation

## Several browser clients

The author has confirmed successful use of three simultaneous browsers; see
[the manual validation record](validacao-manual.md). Profile and detailed scenario
measurements can be added there without inferring unreported observations.

Start the normal stack with `docker compose up -d`. Open three browser windows at
http://localhost:8080/, select videos (including different movies) and start
simultaneous playback. Test seeking in one window while the others continue.

Record the selected suite, number of clients, video names, whether playback/seek
worked independently and the relevant proxy metrics. Browser windows are a manual
functional concurrency test; they are not a controlled throughput benchmark.
Several windows use the same proxy process. The additional Step 5 case of several
independent proxy instances requires starting several proxy processes/containers
against one common server. Do not describe three windows as three proxy instances.

## Full-file volume and throughput

Browser playback produces ranges, buffering and cancelled requests. For one
repeatable full-download observation, use an existing video and the same environment:

```sh
mkdir -p build
curl --fail --silent --show-error \
  --output build/received.mp4 \
  --write-out 'HTTP %{http_code} | bytes %{size_download} | seconds %{time_total} | bytes/s %{speed_download}\n' \
  http://localhost:8080/video/sintel.mp4
shasum -a 256 media/sintel.mp4 build/received.mp4
```

Use `sha256sum` on Linux. The original and received digests must match. In a completed
full response, original file length, accepted plaintext bytes and forwarded bytes
must agree. Authenticated/forwarded DATA block counts must agree too.
Protocol volume is larger because it includes metadata, END, headers, sequences,
subtype bytes and authentication tags; it excludes handshake and TCP/IP overhead.

The proxy's duration starts after the handshake and includes stream reception,
authentication/decryption and browser output. curl's total time starts before
opening its HTTP connection and includes the secure handshake. These are different
intervals; identify the one used in the report. curl reports bytes/s; divide by
1000 for decimal kB/s or 1,000,000 for MB/s.

For exact byte counts rather than rounded terminal summaries, enable detailed
metrics explicitly before the experiment:

```sh
METRICS_FORMAT=detailed docker compose up -d --force-recreate
docker compose logs --no-log-prefix proxy
```

Return to the concise view afterwards:

```sh
METRICS_FORMAT=summary docker compose up -d --force-recreate
```

Keep the file, host, block size and concurrency fixed when comparing profiles.
Repeat downloads, identify warm-up runs and record variation. Use the baseline
proxy's delay argument `0` when comparing to plaintext; its reference default is
2000 ms/read, which deliberately slows playback. The baseline is a separate
`server`/`proxy` command pair documented in README; avoid port conflicts with Docker.
Do not mix aborted/range traffic with complete full-file measurements.

## Byte ranges and interruptions

To inspect a 1024-byte range independently:

```sh
curl --fail --include --range 0-1023 http://localhost:8080/video/sintel.mp4 --output build/range-response.bin
```

The saved response includes HTTP headers, so it is not a raw MP4 chunk. Expected
status is 206 and Content-Range identifies the selected bytes and total size.
Normal browser seeking can close an old response and open another range request.
A Broken pipe at a browser write records that the connection closed; it does not
by itself identify an attack or a crypto failure. Investigate repeated interruptions
that cannot be explained by browser/network activity rather than hiding them.

## Why authenticated and forwarded block counts can differ

The receiver holds one block pending until another block arrives or END validates.
For example, while handling authenticated block 4 it writes pending block 3. If the
browser has disconnected, that write fails. Blocks 1 and 2 were fully written;
blocks 3 and 4 were authenticated but have no completed browser write. The summary
therefore shows 4/2. This is not two extra packets or duplicated output.

TCP packetization and retransmission are handled below the application. These
counters describe encrypted DATA records and successful write/flush operations,
not TCP packets or proof of browser playback. On a failed write some bytes might
already have reached the socket; forwarded counts conservatively include only
fully successful block writes. On valid END and successful output, counts agree.

## Security validation

Opening windows checks functionality/concurrency; it cannot demonstrate rejection
of forged tags, replayed records or truncation. Those cases remain ordinary Kotlin
unit/integration tests, run with `./gradlew test`. They use in-memory record changes
and controlled test sockets, not a Python attack tool. The Gradle HTML report is
`build/reports/tests/test/index.html`. See [threat-model.md](threat-model.md).
