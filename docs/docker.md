# Run with Docker Compose

Docker Compose runs two containers using the same application image. No Kotlin
classes or protocol code were changed for this deployment.

```text
Browser -> localhost:8080 -> proxy container
                            -> stream-server:8082 -> stream-server container
```

## Start and stop

Requirements: Docker with Compose, the project files, a matching private XML pair,
and a media directory. Local JDK, Gradle and Python are not required to start the
containers. The first build needs internet access to download base images, Gradle
and dependencies. Put browser-compatible MP4 files directly inside `media/`.

From the project root:

```sh
docker compose up -d
```

The default profile is `config/profiles/aes256-gcm/`. This workspace already has
its private pair. On a fresh checkout, first provision `proxy.config` and
`server.config` from that folder's templates following [config/README.md](../config/README.md).
No private keys are embedded in the image or supplied as public defaults.
Missing mount paths cause an error rather than silently creating empty directories.

The initial `up` builds a missing application image; subsequent runs reuse it.
For an explicit rebuild after changing source/build files:

```sh
docker compose up -d --build
```

Check startup, then open http://localhost:8080/:

```sh
docker compose ps
docker compose logs -f proxy stream-server
```

Readiness checks inspect Linux TCP listeners without generating fake handshakes.
The proxy is started after the server's listener is healthy. These checks verify
listening sockets, not cryptographic agreement or video playback; the check below
exercises the application. An invalid local XML causes startup to fail; mismatched
valid peer configurations fail when a secure request is attempted.

Stop only this Compose project:

```sh
docker compose down
```

This removes the project's containers/network and preserves host XML/media files
and the built application image. Docker services from other projects are unrelated.
If a local Gradle proxy already occupies 8080, stop that process or select another
host port using PROXY_PORT below.

## What each file does

- `Dockerfile`: builder stage uses JDK 21 and the Gradle Wrapper to run installDist.
  Runtime stage contains JRE 21 plus the generated launcher/libraries. It starts
  `/app/bin/SSC_workAssignment`; Compose supplies the role and existing arguments.
- `.dockerignore`: allows only build files, the Wrapper and main sources into the
  build context. XML credentials, videos, Git history and test fixtures are excluded.
- `compose.yaml`: describes the two services, shared image, arguments, read-only
  bind mounts, listener checks, dependency and browser port mapping. The server
  builds `ssc-wa1:local`; the proxy reuses that image rather than a second build.
- `.env.example`: optional public choices for profile, browser port and media path.
  Copy to `.env` to persist choices; `.env` is Git-ignored. It contains paths/names,
  never actual PSKs. Environment variables can also be supplied inline.

Only the stream server sees the media mount and server XML; the proxy sees its
own XML. Both mounts are read-only. The default runtime user can read the private
host files without making mode-0600 keys world-readable. The runtime filesystem
contains no configuration/media copies from the build.

## Addresses and configuration

Inside its container, `localhost` refers to that same container. Therefore the
proxy's existing origin-host argument is `stream-server`, resolved through the
Compose network. The stream server's TCP 8082 is used within that network; only
the proxy's 8080 is published to the host. The HTML, catalog and seeking behavior
remain the same; proxy-to-server uses the custom secure protocol.

Switch profiles without rebuilding the image:

```sh
CRYPTO_PROFILE=aes256-ctr-hmac-sha256 docker compose up -d --force-recreate
```

Both role files come from the same selected folder. Configurations are read at
process startup. After editing XML, use `--force-recreate` to restart the programs
and remount the current file, including editors that save by replacing its inode.
Changing XML alone never requires `--build`.

Examples of other runtime choices:

```sh
PROXY_PORT=8085 docker compose up -d
MEDIA_DIR=/absolute/path/to/videos docker compose up -d --force-recreate
```

Runtime paths are independent of the image. Inside the containers they are always
`/app/config/proxy.config`, `/app/config/server.config` and `/app/media`. The profile
name selects host files, whose XML values remain the actual cryptographic policy.
Persist repeated choices in `.env`, or repeat inline variables in later commands
that must use those choices. Avoid changing an existing stack's settings unintentionally.

The proxy defaults to concise two-line transfer summaries, with routine catalog
success hidden. Follow them with `docker compose logs -f proxy`.
For exact machine-readable counters, explicitly enable detailed output:

```sh
METRICS_FORMAT=detailed docker compose up -d --force-recreate
docker compose logs --no-log-prefix proxy | rg 'event=stream_metrics'
```

See [stream-metrics.md](stream-metrics.md) for field definitions and throughput methodology.

## Quick functional verification

With the stack running, open http://localhost:8080/, select videos and test playback
and seeking. Open three browser windows for simultaneous playback. To verify exact
full-file transfer separately, substitute an existing filename:

```sh
mkdir -p build
curl --fail http://localhost:8080/video/sintel.mp4 -o build/received.mp4
shasum -a 256 media/sintel.mp4 build/received.mp4
```

On Linux, use `sha256sum` instead of `shasum -a 256`. The two digests should match.
For a different published proxy port, substitute that port in the URL. See
[manual measurement](performance.md) for Range requests and timing commands.

Unit/adversarial tests remain available with `./gradlew test`; image building
compiles/packages main code and does not run the test suite. Docker packaging
preserves the same code paths, threads, handshake and record cryptography.

## Separate physical hosts

This Compose file demonstrates two isolated processes on one Docker host. It is
not a test between physical computers. The image can also run each role separately
on different hosts: publish TCP 8082 for the server and pass its reachable host/IP
to the proxy instead of the Compose service name. Mount each role's matching XML
and mount media only into the server. See [distributed execution](secure-browser.md#run-on-two-physical-machines)
for addressing, provisioning and verification; Docker service-name DNS here is
local to this Compose network.

## Primary references

- Compose startup and healthy dependencies: https://docs.docker.com/compose/how-tos/startup-order/
- Compose services and bind mounts: https://docs.docker.com/reference/compose-file/services/
- Compose build behavior: https://docs.docker.com/reference/compose-file/build/

## Concurrency and baseline comparison

Use [manual validation](performance.md) for concurrent browser playback and
repeatable full-download measurements. Automated adversarial checks stay in the
Kotlin test suite (`./gradlew test`); no Python tooling is required.
