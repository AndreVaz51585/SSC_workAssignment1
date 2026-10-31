# Threat model and reproducible adversarial tests

The Portuguese walkthrough is [matriz-ameacas.md](matriz-ameacas.md). The author's
three-browser observation is in [validacao-manual.md](validacao-manual.md).

## Scope and assumptions

Protect proxy-to-stream-server traffic from an attacker who can observe, modify,
inject, replay, reorder or remove protocol records and close the connection.
The attacker does not know the provisioned secrets or control either endpoint.
Secrets are provisioned out of band; DH keys/randoms are fresh and providers and
random generation are trusted. Browser-to-proxy HTTP is outside the encrypted channel.

PSK authentication proves possession of a shared credential, not human identity.
It cannot distinguish two machines provisioned with the same secrets. Endpoint
compromise, stolen live session keys and denial of service are outside the channel's
confidentiality/authentication guarantee. Bounds/timeouts mitigate some resource
abuse; the cached worker pools are not a complete DoS defense.

## Dedicated adversarial class

[adversarialTest.kt](../src/test/kotlin/ssc/adversarial/adversarialTest.kt) contains
one named method per attack scenario. Method names begin with C0/A1a/.../A7c for
simple navigation and demonstration. Some methods iterate over five representative
profiles: AES-256-GCM, ChaCha20-Poly1305 and AES-256-CTR with HMAC-SHA256/384/512.
C0 first provides a successful authorized-peer transfer control.

The existing primitive/state/configuration tests remain in their specific classes.
Handshake and HTTP functional tests share the same test plumbing through
[ProtocolTestSupport.kt](../src/test/kotlin/ssc/support/ProtocolTestSupport.kt).
Attacker scenarios were moved out of the old mixed handshake/HTTP classes rather
than keeping the previous compound attack loop as a duplicate demonstration.

| Threat | Mechanism and required observation | Dedicated evidence |
| --- | --- | --- |
| Impersonation without secrets | Valid-size guesses pass local config validation; Type 1 authentication fails; no server session | A1a: guessed SKey and, for CTR, guessed MacKey; alert 255 observed |
| Partial credential knowledge | Possessing SKey alone does not supply the configured CTR authentication root | A1b: correct SKey, wrong MacKey |
| Modify public handshake fields | Authentication binds proposal/DH key/public server random | A2a proposal; A2b a genuine attacker DH key substituted without recomputing tag; A2f public server random |
| Modify protected handshake | Failed tag verification prevents acceptance | A2c ServerHello tag; A2d ClientFinished tag |
| Wrong handshake state | Expected message type enforced | A2e Type 3 injected in place of initial Type 1 |
| Alter media or metadata | No altered content released; metadata failure precedes origin HTTP headers | A3a ciphertext; A3b DATA tag; A3c metadata tag (HTTP 502, empty body) |
| Replay records or old handshake | Sequence/session binding rejects replay | A4a duplicate DATA; A4b previous Type 2; A4c previous Type 3 |
| Missing/out-of-order records | Exact sequence enforcement leaves incomplete body | A5a remove DATA; A5b swap DATA |
| Truncation or false termination | Require valid END and exact authenticated length | A6a missing END; A6b altered END |
| Invalid binary framing | Reject oversized length before reading/allocating its body; reject partial/unknown headers | A7a length; A7b truncated header; A7c unknown type |

A1a models an attacker supplying guesses, not an absent key rejected only by the
XML parser. A2b uses a valid DH key in the configured group: rejection is due to
ClientHello authentication, not merely an invalid DH encoding/group. This supports
the MITM-resistance argument; it is not a full live two-leg MITM experiment.

A2d/A4c require server rejection. The proxy may already have returned after sending
Type 3; it has no fourth handshake acknowledgment. Authenticated stream metadata
provides subsequent server confirmation. Do not claim both sides necessarily throw
inside perform() for every Type 3 attack.

## How test interception works

`ProtocolTestSupport.FrameFilter` is test-only. It buffers each serialized frame
and transforms it at the protocol writer's flush before delivery to the socket.
The application protocol classes handle the resulting bytes normally.
Individual tests expose the actual transformation: flip a bit, substitute a public
key, repeat/omit bytes, hold a record and send it after its successor, or omit END.
The tests assert the mutation occurred when applicable.

For DATA/END attacks, metadata arrives valid first. HTTP may already have status
200/206; failure then closes that response rather than appending a second status
line. `expectIncompleteHttp` requires a body shorter than its announced length and
exactly equal to an authentic source prefix. Earlier valid records can have been
delivered. A nonempty body's final block is held until END validates.

This changes application records, not IP packets. TCP normally repairs packet
loss/reordering; application-record transformations directly exercise protocol
security state. No Python attack driver or production attack mode is used.

## Additional evidence and design analysis

- Primitive vectors and corrupted AAD/IV/key/tag tests: aeadCipherTest and
  messageProtectionTest. These are correctness evidence, not a formal
  confidentiality proof or a passive-capture demonstration.
- Nonce/counter uniqueness, key separation and record-restart/overflow rejection:
  messageProtectionTest and secureStreamTest.
- Authenticated-but-incompatible policy proposals: handshakeTest, outside the
  unknown-PSK attacker scenarios. That test deliberately knows a test key.
- XML validation: cryptoConfigLoaderTest, cryptoConfigValidatorTest, cryptoProfilesTest.
- Path traversal/symlink and concurrent browser requests: secureHttpTest.

Forward secrecy is a design argument based on fresh authenticated DH, secure DH
and nonretention of ephemeral secrets. It is not proven by round-trip tests.
JVM secret clearing is best effort. Replaying initial Type 1 can trigger a fresh
server response; the guarantee is not that every duplicate ClientHello is
immediately rejected, but that captured responses cannot complete a fresh session.
Dropping traffic can deny service; detection does not restore availability.

## Execute and present

Run the dedicated class from IntelliJ or from the project root with JDK 21:

```sh
./gradlew test --tests 'ssc.adversarial.adversarialTest' --console=plain
```

Run only the impersonation scenario:

```sh
./gradlew test --tests 'ssc.adversarial.adversarialTest.test A1a*' --console=plain
```

Then run the full suite for the global final report:

```sh
./gradlew test --console=plain
```

Gradle HTML: `build/reports/tests/test/index.html`; XML: `build/test-results/test/`.
Filtered runs report only that subset. Method counts are not counts of every
profile combination. A green negative test means the intended invalid exchange
was rejected according to its assertions, not that an attacker succeeded.

## Remaining delivery work

Record the manual scenario/profile/metrics and explain the security mechanisms,
observed rejections and limits in the assignment report. Verify clean-checkout
configuration/provisioning and prepare the required submission archive. Separate
physical-host instructions already exist; an actual run must be recorded as such
if performed. Do not describe automated evidence as manual browser observations.
