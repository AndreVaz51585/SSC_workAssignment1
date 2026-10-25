# Local cryptographic configuration: parsing and policy

This increment defines configuration rules, not a working secure channel. Streaming
is still plaintext: Main and the socket handlers have not been wired to these rules.
Passing validation does not claim handshake, encryption, replay protection or nonce
uniqueness have been implemented.

## Organization

- `config/dto/CryptoConfig`: parsed values, including decoded key material.
- `config/CryptoConfigLoader`: XML structure, primitive conversions and key decoding.
- `config/CipherSuite`: centrally defined planned profiles, algorithm families,
  protection categories and nonce requirements.
- `config/CryptoConfigValidator`: local semantic rules and JDK primitive availability.
- `ValidatedCryptoConfig`: configuration plus resolved suite/MAC metadata, for later
  handshake integration. It does not establish agreement with a peer.

Use `CryptoConfigValidator.validate(CryptoConfigLoader.load(path))` in code when
ready to integrate. Invalid configurations throw IllegalArgumentException with
messages that omit secret values.

## Planned profiles

| XML algorithm/mode | AES/ChaCha key bits | IVSize (bits) | Padding | MAC |
| --- | --- | --- | --- | --- |
| AES/GCM | 128, 192, 256 | 96 | NULL or NoPadding | All separate MAC fields NULL |
| ChaCha20/Poly1305 | 256 | 96 | NULL or NoPadding | All separate MAC fields NULL |
| AES/CTR | 128, 192, 256 | 128 | NULL or NoPadding | HMAC-SHA256, HMAC-SHA384 or HMAC-SHA512 |

These profiles are candidates for incremental implementation. Acceptance by the
validator is not equivalent to complete streaming support. Other profiles, such as
AES/CBC, are rejected as outside this implementation's current scope, rather than
being described as intrinsically invalid.

AES remains a block cipher in GCM/CTR modes, even though no plaintext padding is
needed. ChaCha20 is a stream cipher. This family classification is distinct from
whether the whole construction is AEAD or Encrypt-then-MAC.

## Explicit project policies

- GCM is restricted to 96-bit IVs by this protocol policy, following NIST's
  recommendation. This is not a universal GCM requirement.
- IETF ChaCha20-Poly1305 uses 96-bit nonces. Its integrated Poly1305 tag does not
  use the separately configured MAC key.
- AES/CTR uses a 128-bit counter block. Future implementation must ensure counter
  ranges do not overlap across messages, including increments inside a message.
  Merely incrementing each message's initial counter by one is insufficient.
- IV must be NULL in all current XML profiles: fixed reusable IVs are deliberately
  unsupported. IVSize describes the future runtime nonce/counter representation.
  Fresh per-session directional keys and nonce management still need implementation.
- AEAD uses an integrated authentication tag; separate MAC fields are NULL by
  project policy, not because adding any external MAC is mathematically impossible.
- HMAC keys must have at least 256/384/512 bits for SHA-256/384/512 respectively,
  and a whole number of bytes. These conservative minimums are project policies.
- Keysize and MacKeySize must match the actual decoded bytes. SKey is provisionally
  the bootstrap PSK and its declared size also selects the intended traffic-key
  size. Session traffic keys will be DH/KDF-derived rather than these static bytes.
- CTR's configured MacKey is an independent initial secret, not the final session
  MAC key. Its precise use in the authenticated key schedule must be specified
  before implementing the CTR profile. Runtime encryption/MAC keys must be separate
  and derived for each direction/session. Equality of configured secrets is rejected;
  their independent generation is an operator responsibility, not provable by XML.
- Accepted HMAC names include both the assignment spelling `HMAC-SHA256` (etc.) and
  the JCA spelling `HmacSHA256`. Algorithm/mode matching is case-insensitive.
- Key text supports encoding="hex" or encoding="base64". Missing encoding defaults
  to hex. XML text NULL maps to absence, not to a key containing those four letters.
- Role roots are ProxyCryptoConfig / ServerCryptoConfig, version 1.0. IVSize uses
  unit="bits", correcting the malformed illustrative tag in the assignment.

The config schema preserves the assignment's main sections. The encoding attribute,
corrected tag spelling, initial-key interpretation and dynamic-IV policy are explicit
project decisions. Key agreement/authentication/KDF settings and tag lengths still
need configuration fields when the complete handshake is specified; they are not
silently fixed by this validator.

## Tests and private configuration

Tests keep the package/class organization established in the project. Loader tests
use public deterministic XML fixtures in src/test/resources/config; validator tests
construct configurations directly. Test bytes must never be used for real sessions.
Local config/*.config files remain private and ignored by Git. No real PSK is needed
to run the tests on a fresh checkout.

## References

- Assignment sections 2.2.2, 2.2.4 and 5 (configuration and incremental validation).
- NIST SP 800-38D, section 5.2.1.1: recommended 96-bit GCM IV restriction:
  https://csrc.nist.gov/pubs/sp/800/38/d/final
- RFC 8439, section 2.8: IETF ChaCha20-Poly1305 key and nonce inputs:
  https://www.rfc-editor.org/rfc/rfc8439.html#section-2.8
- NIST SP 800-38A, section 6.5 and Appendix B: CTR counter uniqueness:
  https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
- JDK 21 standard names (JCA transformations and MAC names):
  https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html
