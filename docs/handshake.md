# Authenticated handshake: first integrated increment

This is an academic application protocol built from JCA primitives, not TLS or a
production-audited protocol. This increment establishes matching session keys over
sockets. The plaintext HTTP baseline remains available. The secure browser commands and Types 4/5 are now implemented
in the [protected file-transfer increment](secure-stream.md).

## Assignment requirements and project choices

The assignment reference fields are retained in order: Type 1 SEQX/PCC, Type 2
SEQY/SRV/CCC, Type 3 SEQZ/R/MEDIA. Protocol version/release are 1:1. The Type 2/3
bodies are encrypted, errors use Type 255, and DH public values are authenticated.

The assignment does not completely specify an authenticated DH wire format or key
schedule. The following are explicit project extensions, not quoted requirements:

- DH public keys, clientRandom and a Type 1 HMAC.
- Extra public proposal fields for key/IV sizes, MAC selection and handshake profile.
- A public serverRandom prefix in Type 2 to derive its initial protection keys.
- Binding header bytes and handshake transcript hashes to authentication.
- A 4-byte signed non-negative payload length and 8-byte signed non-negative sequence.
- The Handshake XML section. Both sides must use the same public security profile.

The proposed assignment configuration string is encoded as ALG/MODE/NULL/Padding,
where absent padding is the text NULL. Extra configuration fields follow it. The
full private XML is NEVER transmitted.

## Code map

- ProtocolMessageCodec: the outer 9-byte header and payload framing.
- HandshakePayloadCodec: canonical binary field encoding for each clear payload.
- HandshakeCrypto: SHA-256, HMAC-SHA256 and HKDF operations.
- MessageProtection: selected-suite protection (AEAD via AeadCipher, or AES-CTR/HMAC Encrypt-then-MAC).
- HandshakeKeySchedule: which inputs, labels and contexts produce each key/IV.
- ProxyHandshake / ServerHandshake: ordered send/receive/verify operations.
- HandshakeSession: resulting directional traffic keys, requested media and next sequence.
- HandshakeDemo: standalone CLI/socket exercise, separate from video streaming.

## Bytes and lengths

The header is version(2) || release(2) || type(1) || payloadLength(4), big-endian.
Each variable-length field is length(4) || bytes. Text is ordinary UTF-8, decoded
strictly. Strings and public key encodings are limited to 1024 bytes. Unknown/trailing
fields, incomplete messages and oversized lengths are rejected before processing.

DH public bytes use the JDK's X.509 SubjectPublicKeyInfo encoding, not certificates
and not UTF-8 strings. A received key must have the configured group's exact p/g,
2 <= y <= p-2 and subgroup membership y^q mod p = 1, q=(p-1)/2.

## Type 1: proxy -> server

The clear body is:

    SEQX(8) || proposal || clientRandom(32) || length-prefixed public A

SEQX starts at a random non-negative 31-bit value, carried in a 64-bit field.
clientRandom comes from SecureRandom. A new DH pair is generated for each attempt.

Derive a client-authentication key from the PSK using HKDF-SHA256 with a distinct
label. Compute HMAC-SHA256 over the FINAL header (including the tag in payloadLength)
and the clear body. Append the 32-byte HMAC to the body. The HMAC does not cover itself.

The server bounds/decodes fields, verifies the HMAC using MessageDigest.isEqual,
checks the exact proposed public configuration against local policy, then performs DH.
A PSK shared by several proxies authenticates membership in that credential group,
not a unique human identity. PSK provisioning is an out-of-band trust assumption.

## Type 2: server -> proxy

The encrypted clear body is:

    SEQY(8) || SRV(32) || confirmation || length-prefixed public B

SEQY=SEQX+1. SRV is the assignment's 256-bit challenge. The server also generates an
independent 32-byte public serverRandom, sent before the ciphertext:

    header2 || serverRandom || ciphertext2 || authentication tag

The two random values have distinct roles: serverRandom is available before
decryption; SRV is recovered from the encrypted body and checked through Type 3.

Bootstrap key derivation (conceptual notation):

    bootstrapPRK = HKDF-Extract(SHA256(clientRandom || serverRandom), PSK)
    key2 = HKDF-Expand(bootstrapPRK, label("server hello key") || SHA256(frame1), keyBytes)
    iv2  = HKDF-Expand(bootstrapPRK, label("server hello iv")  || SHA256(frame1), 12)

The exact label encoding is centralized in HandshakeKeySchedule (domain prefix,
label, zero separator, context). The public header, serverRandom and SHA256(frame1)
are authenticated as associated data. Tampering changes the key or invalidates
the tag. The fresh serverRandom changes the bootstrap key/IV even for a replayed
Type 1; no fixed PSK/IV pair is reused to encrypt different server responses.

For AEAD, Cipher.doFinal adds/verifies the tag. For CTR/HMAC, MessageProtection
authenticates the associated data, IV and ciphertext before invoking CTR decryption. No redundant ServerHello
HMAC field is stored inside the plaintext DTO. The proxy must verify SEQY and the
exact configuration confirmation after decryption.

## Session secret and Type 3: proxy -> server

After processing Type 2, both parties have the two DH public keys, their own private
key, clientRandom and SRV. Both calculate Z using local private + remote public.
They derive a context-bound handshake secret as implemented in HandshakeKeySchedule:

    authenticationRoot = HKDF-Extract(SHA256(clientRandom || SRV), PSK)
    combined = HKDF-Extract(authenticationRoot, Z)
    handshakeSecret = HKDF-Expand(combined, handshake-secret label || SHA256(frame1 || frame2), 32)

The Type 3 body is:

    SEQZ(8) || SHA256(SRV)(32) || length-prefixed MEDIA || hasRange(1) || [length-prefixed Range]

SEQZ=SEQX+2. It is protected with the selected authenticated protection suite under a separate client-finished key/IV derived
from handshakeSecret and the hello transcript hash. AAD is header3 || helloHash.
The hash response follows the assignment example; the hash alone is not identity
proof. The authenticated, fresh, transcript-bound envelope supplies that protection.

The optional Range suffix is a project extension for browser integration. It is encrypted
and transcript-bound with the rest of Type 3 (see secure-browser.md).

The server verifies the tag, sequence, challenge response, media name and optional Range BEFORE
returning a session to the caller. No stream is sent during the standalone demo.

## Directional traffic keys and confirmation

After Type 3 is sent/validated, hash all three complete frames. Derive separate
proxy->server and server->proxy traffic keys/IV bases, using distinct labels and
this full transcript hash. These keys are distinct from bootstrap and finished keys.
The first stream record (metadata) uses SEQX+3. The first media DATA record then
uses SEQX+4. HandshakeSession.firstMediaSequence names the first stream-record
sequence for compatibility with the earlier increment.

Each handshake protection key/IV is used for one encryption. Per-record counters
and nonce uniqueness for traffic keys are implemented by the separate streaming
layer (see secure-stream.md); returning an IV base alone does not implement them.

There are exactly three handshake messages. The proxy knows it authenticated Type 2
and sent Type 3, but cannot know Type 3 was accepted until a protected server record
arrives. The CLI states this explicitly; the tests can also observe the server result.

Replay of old Types 2/3 fails in a fresh transcript/key context. A replay of a valid
Type 1 can initiate a NEW challenge exchange; it cannot complete it using the old
Type 3. No persistent ClientHello replay cache or DoS mitigation is claimed here.

The Handshake XML also requires MaxStreamRecords for the record layer; see secure-stream.md.

## Failure behavior and limits

Any protocol/crypto failure aborts and attempts to send a generic Type 255 alert.
Before a session is established, alerts are not authenticated: they are diagnostic
only, never grounds for weakening configuration, retrying with a weaker profile or
accepting a session. Caller closes the connection on failure. Timeouts and message
limits are configured; malformed input never leads to plaintext fallback.

The integrated profiles use AES-GCM (128/192/256-bit keys), ChaCha20-Poly1305
(256-bit keys), or AES-CTR (128/192/256-bit keys) with HMAC-SHA256/384/512.
All use ffdhe2048, HKDF-SHA256 and HMAC-SHA256 handshake authentication. AEAD tags
are 128 bits; CTR uses the full selected HMAC tag. The XML declares
these settings; unsupported combinations fail before opening the demo socket.

The secure-stream commands protect file data with Types 4/5. The original server/proxy
commands still run the plaintext HTTP baseline. No user login or Authentication Server is implemented.
Session compromise, threat coverage and measurements remain to be evaluated in the
complete project. Ephemeral DH avoids deriving traffic keys solely from the PSK;
future PSK compromise plus recorded traffic does not by itself reveal DH Z, assuming
DH remains secure and ephemeral secrets are not retained. JVM memory erasure is not
guaranteed; byte-array clearing is best effort.

## Run the exercise

From the project root, with the matching private XML configurations:

Terminal 1 (one connection, then exits):

    ./gradlew run --args="handshake-server"

Terminal 2:

    ./gradlew run --args="handshake-proxy localhost 8082 sintel.mp4"

The media name is requested but the demo does not read/send the file. Both terminals
should show the same public transcript-derived session ID, never the keys. This is
a separate port from the existing video service, so it does not silently replace it.

## Reading the less obvious instructions

- writeInt / writeLong: fixed-width binary integers, not decimal text. They delimit
  fields unambiguously and preserve the assignment's concatenation order.
- UTF-8 encode/decode: only for text fields; public keys and ciphertext stay binary.
- X509EncodedKeySpec: reconstructs a public-key object from a standard key encoding;
  it does not validate a certificate or establish peer trust.
- init(privateKey), doPhase(remotePublicKey, true), generateSecret(): local agreement
  computation, not a network exchange and not authentication.
- SecureRandom.nextBytes: fresh unpredictable random input. No manual seed is used.
- HKDF Extract/Expand: mix secret inputs and derive different outputs by role/context.
- updateAAD: authenticate clear metadata before doFinal processes the ciphertext.
- doFinal on decrypt: verifies the AEAD tag; failure aborts before plaintext is used.
- MessageDigest.isEqual: comparison intended for authentication bytes without early
  exit on the first differing byte.
- SHA256(frame1 || frame2): binds keys/messages to the precise handshake transcript.
- require: fail closed on an invalid state, parameter or authenticated field.

## Primary references

- RFC 7919 Appendix A.1, ffdhe2048 group:
  https://www.rfc-editor.org/rfc/rfc7919.html#appendix-A.1
- RFC 5869, HKDF (implementation checked against published vectors):
  https://www.rfc-editor.org/rfc/rfc5869.html
- JDK Cipher API, AEAD/AAD/tag behavior:
  https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Cipher.html

## CTR/HMAC extension

For CTR profiles, the configured independent SKey and MacKey are combined as
`HKDF-Expand(HKDF-Extract(MacKey, SKey), authentication-root-label, 32)`.
This authentication root replaces the PSK input in the schedule above. Public
proposal fields include the selected HMAC and key size. Type 1 authentication
remains HMAC-SHA256; Types 2/3/4/5 use the selected record protection.
Every protected phase/direction derives an additional independent MAC key under
its own HKDF label. Type 2 and Type 3 each have a single-use key/IV pair.
Traffic CTR counters reserve a separate 64-bit prefix per sequence, with the
internal block counter starting at zero. See [crypto-profiles.md](crypto-profiles.md).
