# Cryptographic profiles

Each folder under `config/profiles/` contains a matched pair:
`proxy.config` and `server.config`. The application reads the XML at startup;
the folder name is only an organizational label. Both peers must use matching
public cryptographic settings and provisioned secrets.

| Folder | Encryption key | IV/counter | Authentication tag |
| --- | --- | --- | --- |
| aes128-gcm | 128 bits | 96 bits | integrated, 128 bits |
| aes192-gcm | 192 bits | 96 bits | integrated, 128 bits |
| aes256-gcm | 256 bits | 96 bits | integrated, 128 bits |
| chacha20-poly1305 | 256 bits | 96 bits | integrated, 128 bits |
| aes128-ctr-hmac-sha256 | 128 bits | 128 bits | HMAC-SHA256, 256 bits |
| aes192-ctr-hmac-sha256 | 192 bits | 128 bits | HMAC-SHA256, 256 bits |
| aes256-ctr-hmac-sha256 | 256 bits | 128 bits | HMAC-SHA256, 256 bits |
| aes256-ctr-hmac-sha384 | 256 bits | 128 bits | HMAC-SHA384, 384 bits |
| aes256-ctr-hmac-sha512 | 256 bits | 128 bits | HMAC-SHA512, 512 bits |

The CTR engine accepts every supported AES key size with every supported HMAC.
These nine folders are representative ready-to-run configurations, not every
possible combination. There is no need to add more algorithms to demonstrate
configuration changes without recompilation.

## Run a pair

Run these in separate terminals from the project root with JDK 21:

```sh
./gradlew run --console=plain --args="secure-server 8082 media config/profiles/aes256-ctr-hmac-sha256/server.config"
```

```sh
./gradlew run --console=plain --args="secure-proxy 8080 localhost 8082 config/profiles/aes256-ctr-hmac-sha256/proxy.config"
```

Open http://localhost:8080/. To change profiles, stop both processes and select
another matching folder. The same compiled binary handles every profile.
The legacy default files `proxycrypto.config` / `sservercrypto.config` remain valid.

## Private keys and fresh checkouts

Local `.config` files contain independently generated random secrets per profile;
both endpoints of a pair have identical secrets. They are Git-ignored and newly
provisioned files have permissions 0600. `proxy.config.example` and
`server.config.example` in each folder are versionable placeholder templates.

On a fresh checkout, copy the templates to `proxy.config` / `server.config` in
the same folder. Replace each SKey placeholder with the SAME random value for
both peers, using the size required by the profile:

```sh
openssl rand -hex 16  # AES-128
openssl rand -hex 24  # AES-192
openssl rand -hex 32  # AES-256 / ChaCha20
```

For CTR, also generate an INDEPENDENT MacKey, copied to both peers:

```sh
openssl rand -hex 32  # HMAC-SHA256
openssl rand -hex 48  # HMAC-SHA384
openssl rand -hex 64  # HMAC-SHA512
```

Provision keys out of band; keep files private. Never reuse the public deterministic
fixtures in `src/test/resources/config/profiles/` as deployment credentials.
Templates deliberately fail validation until their placeholders are replaced.

## Validation rules

- AES-GCM: AES/GCM, key size 128/192/256, IVSize=96, TagSizeBits=128.
- ChaCha20-Poly1305: ChaCha20/Poly1305, key size 256, IVSize=96, TagSizeBits=128.
- AEAD: MACSuite Algorithm, MacKey and MacKeySize must all be NULL. Type 1 still
  uses HMAC-SHA256 derived from the PSK for handshake authentication.
- CTR: AES/CTR, key size 128/192/256, IVSize=128, selected HMAC-SHA256/384/512,
  independent MacKey with at least 256/384/512 bits, actual key lengths matching
  their declarations. TagSizeBits must equal the full selected HMAC size.
- All profiles: IV=NULL, Padding=NULL/NoPadding. The XML cannot supply a fixed
  reusable IV. Runtime keys, nonces and counters are derived per session/message.
- The supported handshake profile is ffdhe2048 / HKDF-SHA256 / HMAC-SHA256.
- Invalid XML, inconsistent parameters and unavailable provider combinations fail
  before application sockets open. No weaker suite is substituted.

The server confirms or rejects one authenticated proposal; it does not select
from a preference list. See [implementation details](../docs/crypto-profiles.md)
and [adversarial tests](../docs/threat-model.md).

## Docker selection

`CRYPTO_PROFILE=aes256-ctr-hmac-sha256 docker compose up -d --force-recreate`
selects both external XML files from that profile folder without rebuilding the
image. See [Docker instructions](../docs/docker.md).
