# Protected stream records — Types 4 and 5

**Update:** the browser integration now adds Range to Type 3 and METADATA/DATA
subtypes to Type 4; see [secure-browser.md](secure-browser.md) for the current wire
format. The rules below describe the original record-layer increment unless updated.

This increment transfers an actual file over the SAME TCP connection used by
Types 1/2/3. It supports the validated AES-GCM and ChaCha20-Poly1305 profiles; see [crypto-profiles.md](crypto-profiles.md). The original
`server` / `proxy` HTTP browser baseline is still separate; the new `secure-server` /
`secure-proxy` commands integrate the protected channel with browser HTTP Range/catalog.

## Workflow and files

`SecureStreamDemo.server()` loads/validates its XML, accepts a socket and calls
`ServerHandshake.perform()`. Once Type 3 has been verified, it checks the requested
path stays inside the real media directory (including symlinks), opens the file and
calls `SecureStreamSender.send()`.

`SecureStreamDemo.proxy()` loads/validates its own XML, connects and calls
`ProxyHandshake.perform()`. It then calls `SecureStreamReceiver.receive()` using
the SAME socket input. The first successfully verified record confirms that the
server accepted the handshake. This demo saves media to a new local file; it refuses
to overwrite an existing destination and deletes its newly created file on failure.

| Component | Responsibility |
| --- | --- |
| `MediaBlockPayload` | Sequence and plaintext media block before protection / after verification |
| `EndStreamPayload` | Sequence and random string inside encrypted ENDBLOCK |
| `StreamPayloadCodec` | Binary sequence encoding and strict ENDBLOCK encoding/decoding |
| `StreamRecordProtection` | serverToProxy key, nonce construction, header/sequence/session AAD and GCM |
| `SecureStreamSender.send()` | Read blocks and call `sendBlock()` repeatedly, then `sendEnd()` |
| `SecureStreamReceiver.receive()` | Read Types 4/5 in a loop; verify first, then dispatch to `receiveBlock()` / `receiveEnd()` |

The handshake coordinators were also split by message, without changing their
wire format or key schedule:

- Proxy: `sendClientHello()`, `receiveServerHello()`, `sendClientFinished()`.
- Server: `receiveClientHello()`, `sendServerHello()`, `receiveClientFinished()`.

The `perform()` functions retain the ordered workflow, DH calculation, transcript
hashes, key derivation and result. Helpers return the full frame alongside the
parsed payload where both are needed; Kotlin destructuring of `Pair` allows
`val (first, hello) = receiveClientHello(...)`.

## Keys and nonces

Both endpoints use `session.keys.serverToProxy.key` to encrypt/decrypt server data.
They do NOT use the PSK directly, raw DH Z, Type 2 bootstrap key or Type 3 key.
The proxyToServer traffic key is reserved for the opposite direction.

For each record, including END:

    nonce = serverToProxy.iv XOR (0x00000000 || uint64_big_endian(sequence))

The IV base is 12 bytes. The sequence occupies the last eight bytes of a zero-padded
12-byte value. XOR with a fixed base is injective: distinct sequences give distinct
nonces under this key. No nonce is transmitted separately; the receiver derives it.
The first sequence is SEQZ+1; each subsequent record consumes the next sequence.
END consumes its own next sequence, not the previous data record's sequence.

The XML Handshake section now requires `<MaxStreamRecords>1048576</MaxStreamRecords>`
in the example profiles. This local policy counts all records, including END; its
validated upper bound is 2^32 records. The protocol also rejects signed-Long overflow. Reconnect and establish a NEW handshake before exceeding the limit. This
ceiling is not a performance or security benchmark for indefinitely long streams.
A sender/receiver is single-use, including after a failed operation; HandshakeSession
also prevents creating a second sender/receiver on the same session object. Caller
must not clone a session's keys into another channel or restart counters. Sessions
are not persisted or resumed. Key/IV byte copies are cleared in finally (best effort).

## Type 4 wire format

    header4 || SEQB(8) || GCM(DATA(1) || mediaBlock)

`GCM(...)` means ciphertext || tag. First a METADATA record is sent (see secure-browser.md);
DATA records encrypt a one-byte subtype plus block bytes;
SEQB stays clear and is authenticated. This is the project's explicit interpretation
of the assignment's `SEQB || EncryptedBlock` reference format.

    AAD = exact header bytes || SEQB(8) || sessionId

Header includes version/release/type/length. Changing Type 4 to Type 5, changing the
sequence, or moving a record into another session cannot produce an accepted record.
The receiver requires exactly the expected sequence; replay, reorder and missing
records abort. GCM tag verification completes before any bytes of that block are
written to the media output. A valid prefix can already have been delivered when
a later error occurs; complete-stream success requires valid END.

Data payload length is 8 + 1 + blockBytes + tagBytes. Metadata consumes its own record/nonce. The default media buffer remains
1024 bytes; `send(..., blockSize)` can choose another size within the configured
MaxPayloadBytes bound. MaxStreamRecords is a local limit, like MaxPayloadBytes,
and is not added to the cryptographic proposal or the handshake wire format. Blocks do not need padding or a separate HMAC.

## Type 5 wire format

The reference describes a sequence and encrypted ENDBLOCK. We retain both the
outer sequence and the repeated inner sequence explicitly:

    header5 || SEQF(8) || GCM(SEQF(8) || END(3 ASCII bytes) || randomLength(4) || randomString)

The random string is lowercase hexadecimal from `RandomSizeBytes` fresh random
bytes (currently 32 bytes -> 64 ASCII characters). The length prefix is our binary
encoding choice; it prevents ambiguity. This string is not a key or GCM nonce.
Protection uses the same directional traffic key but a new nonce for SEQF, with:

    AAD = exact header5 bytes || SEQF(8) || sessionId

After tag verification, the receiver checks the repeated sequence, literal END,
exact random-string length/hex alphabet and absence of trailing bytes. Only then
does `receive()` return success. An empty file is valid and sends metadata followed by Type 5.

EOF/partial frame/timeout before authenticated END means incomplete transmission.
Unexpected types, including an unauthenticated Type 255 during streaming, abort;
they are not accepted as END. Streaming failures close the demo connection; no new
protected Type 255 format has been designed in this increment. Missing-file errors
also close the socket rather than claiming successful media delivery.

## Run with an MP4

From the project root with JDK 21 selected and matching private XML files:

Terminal 1 — one transfer, then exits:

```sh
./gradlew run --console=plain --args="secure-stream-server"
```

Terminal 2 — choose an existing MP4 from media/ and a NEW destination:

```sh
./gradlew run --console=plain --args="secure-stream-proxy localhost 8082 sintel.mp4 build/received-sintel.mp4"
```

The two existing `handshake-*` commands still test only the handshake; do not run
both servers on port 8082 simultaneously. The new transfer command prints verified
media byte counts; these are not yet the assignment's complete performance metrics.

Compare the source and received file:

```sh
shasum -a 256 media/sintel.mp4 build/received-sintel.mp4
```

The digests must match. This manual comparison verifies an exact copy; block GCM
and authenticated END supply protocol protection. To repeat, restart the server
and choose a fresh output name (existing files are preserved).

## Validation and remaining work

Tests include empty/partial/multiple blocks, fragmented reads, three AES key sizes,
real TCP handshake plus transfer, altered ciphertext/tags/headers/session context,
replay/reorder/drop, missing/truncated/modified END, malformed authenticated END,
size and counter limits, and attempts to restart a sender or receiver.

Browser integration, authenticated metadata, Range and catalog are implemented
(see secure-browser.md). Per-response instrumentation is described in stream-metrics.md;
AES-GCM, ChaCha20-Poly1305 and CTR/HMAC execution in crypto-profiles.md. Final report
measurements must identify their inputs and timing methodology.

## Selectable protection

Types 4/5 use MessageProtection: AES-GCM, ChaCha20-Poly1305 or AES-CTR with
HMAC-SHA256/384/512. CTR verifies HMAC over context, IV and ciphertext before
decryption. Its record IV uses a distinct 64-bit prefix per sequence and a zero
initial 64-bit block counter; see [crypto-profiles.md](crypto-profiles.md).
