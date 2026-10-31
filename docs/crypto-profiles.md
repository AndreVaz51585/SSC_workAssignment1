# Cryptographic profiles and protection integration

The same handshake, record framing, metadata, HTTP Range logic and END state
machine support AES-GCM, ChaCha20-Poly1305 and AES-CTR/HMAC. Nine example pairs
are organized by folder; [config/README.md](../config/README.md) lists paths,
parameters and key provisioning commands.

## Configuration to encryption

```text
CLI path -> CryptoConfigLoader -> CryptoConfigValidator -> HandshakeConfigValidator
  -> ProxyHandshake / ServerHandshake -> MessageProtection
  -> HandshakeSession(suite, macSuite, directional keys)
  -> StreamRecordProtection -> MessageProtection
```

Filenames do not select the cipher. `CipherSuite` describes supported constructions
and their JCA names, key sizes, IV sizes and nonce requirements. `MacSuite` describes
the HMAC algorithms, minimum key sizes and full tag sizes.

1. Loader: bounded XML, expected role/root/version, direct child tags, duplicates,
   unknown elements/attributes, numeric values and key encoding. DTD/entities are
   disabled. Placeholders and malformed key values fail without logging secrets.
2. Crypto validator: resolve the catalog entry, check padding/IV policy, legal key
   sizes and actual decoded lengths. AEAD requires NULL extra-MAC fields. CTR
   requires an independent MAC secret, supported HMAC and consistent size fields.
3. Handshake validator: validate group, KDF, authentication, tag/random size,
   message/timeout/record limits; initialize a provider cipher/MAC using dummy
   parameters before opening application sockets. No probe encrypts session data.

## One protection facade

`MessageProtection` exposes encrypt/decrypt and record-nonce construction. AEAD
operations delegate to the existing small `AeadCipher`; CTR adds explicit EtM.
Each operation creates fresh JCA Cipher/Mac instances, so worker threads share no
mutable provider state. No coordinator contains a branch for each named XML file.

| Construction | JCA cipher | Parameters | Authentication |
| --- | --- | --- | --- |
| AES-GCM | AES/GCM/NoPadding | GCMParameterSpec | integrated 128-bit tag |
| ChaCha20-Poly1305 | ChaCha20-Poly1305 | IvParameterSpec | integrated 128-bit tag |
| AES-CTR/HMAC | AES/CTR/NoPadding | IvParameterSpec | independent HmacSHA256/384/512 |

AEAD uses doFinal to authenticate before returning plaintext. CTR encrypts first:

```text
C = AES-CTR(Kenc, IV, M)
T = HMAC(Kmac, domain || aadLength32 || AAD || IV || C)
protected payload = C || T
```

The fixed domain is `SSC-WA1/1:1/ETM` followed by a zero byte; length is big endian.
AAD binds headers, sequence and transcript/session context as appropriate. The IV
is also authenticated. On receive, split C/T, calculate the expected full HMAC,
compare using MessageDigest.isEqual, and only then initialize CTR decryption.
A failed MAC releases no bytes from that record. All failures abort the connection;
no alternate algorithm or plaintext fallback is attempted.

## Independent keys and counters

For AEAD, SKey is the configured bootstrap PSK. For CTR, configured SKey and MacKey
are independent initial secrets combined through HKDF into an authentication root.
The public proposal never transmits either secret. The same authenticated DH and
transcript-bound schedule then derives phase/direction-specific encryption keys,
IV bases and, for CTR, separate MAC keys under distinct HKDF labels. Static
configured MacKey is not used directly to MAC every video record.

Type 1 authentication stays HMAC-SHA256 for every profile. Types 2/3 use distinct
single-use protection keys/IVs; Types 4/5 use server-to-proxy traffic keys.

AEAD record nonce = IV base XOR zero-padded sequence. CTR needs more than different
starting IVs: internal counter values must not overlap. Its 128-bit initial counter
is `(derivedPrefix64 XOR sequence64) || zero64`. Each record therefore reserves a
separate prefix, starting its internal AES block counter at zero. The bounded
record size (at most the configured 1 MiB ceiling) cannot exhaust the low 64 bits;
sequences cannot repeat within a session and record limits require a new session.
Metadata and END each consume a sequence too.

## Agreement and compatibility

The authenticated Type 1 proposal includes algorithm/mode, sizes, HMAC and handshake
settings. The server checks it against its local canonical policy; Type 2 must
confirm exactly that proposal. Transcript hashes bind this agreement into derived
keys. Both peers must share the final selected suite and provisioned secrets.

This is authenticated proposal/confirmation, not preference-list negotiation.
Differently configured peers fail; there is no automatic downgrade. Supporting
lists later would require authenticating offered lists and the selected common
suite, defining selection policy and extending tests. It is unnecessary to run
multiple profiles by choosing matching XML pairs now.

## Evidence and limits

Tests include exact AES-GCM and RFC 8439 ChaCha20-Poly1305 vectors, the first CTR
block from NIST SP 800-38A F.5, all supported AES/HMAC size combinations, altered
ciphertext/tag/AAD/IV/key, counter-range separation, key separation, malformed
configuration, handshake tampering/replays and actual HTTP transfers across all
nine XML profiles. The dedicated adversarial class splits each record attack into its own named test for
AES-GCM, ChaCha20 and all three CTR/HMAC variants. See [threat-model.md](threat-model.md).

Passing tests is implementation evidence, not a formal proof or external security
audit. Performance measurements and the final assignment report remain separate.

## Primary references

- NIST SP 800-38A, CTR, Appendix B and F.5: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
- RFC 8439, ChaCha20-Poly1305 and test vector: https://www.rfc-editor.org/rfc/rfc8439.html#section-2.8.2
- RFC 7366, verify Encrypt-then-MAC before decryption: https://www.rfc-editor.org/rfc/rfc7366.html#section-3
- RFC 5869, HKDF: https://www.rfc-editor.org/rfc/rfc5869.html
