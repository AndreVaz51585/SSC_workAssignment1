# Secure browser streaming and byte ranges

Cipher selection supports AES-GCM, ChaCha20-Poly1305 and AES-CTR/HMAC via named XML profiles;
see [crypto-profiles.md](crypto-profiles.md) and [config/README.md](../config/README.md).

The browser speaks ordinary HTTP to the proxy. The proxy speaks the authenticated
binary protocol to the stream server. It does not send plaintext HTTP GET between
those components. Every browser GET for media/catalog creates a fresh handshake
and one response; the connection closes afterwards. The HTML page is served locally
by the proxy, using the existing page and video selector.

## Run

From the project root, with JDK 21 selected and matching local XML files:

```sh
# Terminal 1: stays running and accepts independent secure sessions.
./gradlew run --console=plain --args="secure-server"
```

```sh
# Terminal 2: stays running and accepts browser HTTP requests.
./gradlew run --console=plain --args="secure-proxy"
```

Open http://localhost:8080/, select a video and play/seek. Stop any previous proxy
using port 8080 and any one-shot handshake/file server using 8082 first.
The old `server`/`proxy` commands remain the plaintext reference baseline.

## Run on two physical machines

The FAQ section 4.5 requires instructions for separate processes on different
physical machines. Two containers on one host provide useful network isolation
but are not a test on two physical machines. The instructions below describe
deployment; they do not claim that a two-host experiment has already been run.

Example: machine A runs the stream server at `192.168.1.20`; machine B runs the
proxy at `192.168.1.30`. Substitute the actual reachable LAN addresses or hostnames.
Both machines need JDK 21 and a copy of this project. On each machine, from the
project root, build the command-line distribution:

```sh
./gradlew installDist
```

Provision a matching configuration pair as described in [config/README.md](../config/README.md).
Machine A needs `config/profiles/aes256-ctr-hmac-sha256/server.config`; machine B
needs the matching `proxy.config`. Public settings and shared secrets must match;
do not generate unrelated secrets independently on each host. Keep credentials
out of Git and transfer them through a trusted channel. Only A needs the MP4 files
in its `media/` directory.

On machine A:

```sh
build/install/SSC_workAssignment/bin/SSC_workAssignment secure-server 8082 media config/profiles/aes256-ctr-hmac-sha256/server.config
```

On machine B:

```sh
build/install/SSC_workAssignment/bin/SSC_workAssignment secure-proxy 8080 192.168.1.20 8082 config/profiles/aes256-ctr-hmac-sha256/proxy.config
```

The existing `ServerSocket(port)` listeners bind to the wildcard address; no code
change is required to accept LAN connections. The network/firewall must permit
TCP 8082 from B to A. A browser on another machine also needs access to B's TCP 8080.
On B, open `http://localhost:8080/`; from another machine, open
`http://192.168.1.30:8080/`. `localhost` always refers to the machine running that
process, so B must use A's reachable address for its origin connection.

For verification, play and seek a video, then on B download one complete file:

```sh
curl --fail http://localhost:8080/video/sample.mp4 -o build/received.mp4
```

Replace `sample.mp4` with an existing filename. Compare SHA-256 of A's original
with B's received file, using `shasum -a 256` on macOS or `sha256sum` on Linux.
Record the hosts, suite, commands and matching hashes if this experiment is run.
Catalog requests also cross the protected channel; browser-to-proxy remains HTTP.

The installed launcher avoids invoking Gradle for each startup. A later container
deployment can run the same launcher with external XML/media mounts. In a Compose
network, the proxy would use the server service name (for example `stream-server`),
because `localhost` inside the proxy container refers to that container itself.

## Follow one request in the code

1. `main()` selects `SecureProxyServer.run()` / `SecureStreamServer.run()`.
   Each loads its own XML and validates it before listening.
2. `SecureProxyServer.handle()` reads a bounded HTTP GET and its optional Range.
   `/` uses `ProxySocketServer.servePage()`. `/catalog` requests the reserved protocol
   resource `/catalog`; `/video/<encoded-name>` decodes and requests a media filename.
3. `relayResponse()` opens a socket and calls `ProxyHandshake.perform(..., media, range)`.
4. Type 3 now encrypts `SEQZ || R || MEDIA || hasRange(1) || [length(4) || Range UTF-8]`.
   Both participants validate the optional header as bounded printable ASCII. Because
   it is inside authenticated Type 3 and the final transcript, it is bound to the
   session and the returned metadata. Earlier peers without this extension are not
   wire-compatible; run both ends from the same project version. No fallback exists.
5. `SecureStreamServer.handle()` completes `ServerHandshake.perform()`, then passes
   `session.media` and `session.rangeHeader` to `SecureMediaSource.open()`.
6. `SecureMediaSource` validates the path, opens the real file and gets its size.
   `MediaRanges.response()` calculates the selected interval and metadata. The file
   channel is positioned at the selected start; no whole-MP4 buffer is created.
7. `SecureStreamSender.send()` emits metadata, then exactly `contentLength` bytes,
   then END. Its loop cannot accidentally send bytes after the requested interval.
8. `SecureStreamReceiver.receive()` verifies the first metadata record before calling
   `onMetadata`. The proxy callback builds/flushes HTTP headers using that description.
9. Subsequent data records are verified/decrypted and written to the browser. Only
   the final block is withheld until authenticated END and length checks pass. This
   ensures a positive-length HTTP body cannot appear complete without a valid END.
10. Both sockets close after one response. Seeking can cancel an old response and
    create a new GET with a different Range and a new handshake. No traffic key or
    record counter is reused across requests. Each accepted connection has its own
    worker and independent state.

## Type 4 subtypes

Every Type 4 remains `header || sequence(8) || GCM(plaintext)` with the existing
AAD/nonce rules. The FIRST plaintext is METADATA; subsequent plaintexts are DATA:

```text
METADATA plaintext (37 bytes, big endian):
  subtype(1)=0 || status(2) || contentTypeCode(1)
  || totalLength(8) || contentLength(8) || rangeStart(8) || rangeEndInclusive(8)
  || acceptRanges(1)

DATA plaintext:
  subtype(1)=1 || media/catalog bytes
```

Absent optional lengths/offsets are -1. Content type codes are 0 (absent),
1 (video/mp4) and 2 (text/plain; charset=utf-8). Codes/flags, lengths, status and
interval consistency are strictly validated. Arbitrary peer-controlled header
strings are never copied into the HTTP response.

Metadata uses sequence SEQZ+1. The first DATA uses SEQZ+2. Each record, including
END, consumes a distinct sequence/nonce. MaxStreamRecords now counts metadata too;
the sender checks the nominal block count plus metadata and END before starting.
Types 4 with DATA before metadata, repeated metadata, unknown subtypes, and END
without metadata are errors. An empty response is metadata followed by END.

This is an explicit project extension: the first stream block carries protected
response metadata, while the remaining stream blocks carry the resource bytes.
It adds no handshake message type and does not modify the assignment's 1:1 header.

## HTTP metadata and range policy

`MediaResponseMetadata` contains status, content type, total resource length,
response length, optional inclusive start/end offsets, and range support.
`Content-Length` is ONLY the resource bytes in this HTTP response. It excludes
metadata records, subtype/sequence bytes, tags, and END. Receiver requires an exact
match before successful completion and rejects overflow before writing a block.

For a 10000-byte file requested with `Range: bytes=1000-1999`, the proxy writes:

```http
HTTP/1.1 206 Partial Content
Content-Type: video/mp4
Content-Length: 1000
Accept-Ranges: bytes
Content-Range: bytes 1000-1999/10000
Cache-Control: no-store
Connection: close
```

Supported cases:

- No Range: 200, full content, no Content-Range.
- `bytes=start-end`: 206, end clipped to the last file byte if needed.
- `bytes=start-`: 206 from start to EOF.
- `bytes=-count`: 206 for the final count bytes (or the full file if shorter).
- A valid range beyond EOF or a zero suffix: 416, no body,
  `Content-Range: bytes */total`.
- Empty file: 200 with Content-Length 0; Range is ignored.
- Malformed, unsupported-unit and multipart Range: ignored, full 200 response.
  No multipart response encoder is added.
- If-Range: no entity validators are implemented, so conservatively ignore Range
  and return full content. Cache-Control is no-store; no ETag/resumption is claimed.
- Missing/forbidden/non-MP4 file: protected 404 metadata and END, no media body.
- GET only; oversized/ambiguous browser headers are rejected with 400. Duplicate
  Range is rejected. Request lines are bounded to 8192 bytes and total headers to
  64 KiB/100 fields. This is a small HTTP frontend, not a general HTTP server.

For Range semantics and permission to ignore Range, see RFC 9110 sections 14.1/14.2:
https://www.rfc-editor.org/rfc/rfc9110.html#section-14

## Failure behavior

Failure before metadata/HTTP headers produces 502. After headers have started,
the proxy aborts/closes the current response; it never appends a second HTTP status
line into MP4 bytes. The one-block holdback keeps positive-length responses short
on missing/invalid END. Already verified earlier blocks may have been delivered;
this is progressive streaming, not whole-file buffering/rollback.

For zero-length bodies HTTP has no body bytes to withhold; the proxy still requires
END internally before reporting a successful secure response. A browser can already
see the authenticated zero-length status/headers before that internal completion.
An old request cancelled by a seek may produce Broken pipe/connection-closed logs;
its session is discarded, never resumed.

Media path validation permits direct .mp4 files only. Canonical paths/symlink targets
must remain within the canonical media root. Outside symlinks are neither listed nor
served. Endpoints/files are assumed uncompromised as in the assignment; concurrent
operator edits of a video are not a snapshot/versioned-resource feature. Unexpected
short reads fail without successful END.

## Checks

```sh
curl -i http://localhost:8080/catalog
curl -D build/range-headers.txt -H 'Range: bytes=1000-1999' \
  http://localhost:8080/video/sintel.mp4 -o build/range.bin
curl http://localhost:8080/video/sintel.mp4 -o build/browser-copy.mp4
shasum -a 256 media/sintel.mp4 build/browser-copy.mp4
```

Tests exercise real sockets and crypto through the HTTP frontend, exact range bytes,
closed/open/suffix/huge/invalid/multipart ranges, 416/404/empty/catalog/Unicode,
traversal/symlinks, concurrent requests, metadata tampering, END tampering, length
mismatch and record ordering. Existing key/nonce/replay/framing tests remain active.
AES-CTR/HMAC is integrated; see [crypto-profiles.md](crypto-profiles.md).
Per-response proxy metrics are implemented; see [stream-metrics.md](stream-metrics.md).
Comparative performance experiments remain separate project work.
