# SSC Work Assignment 1

Kotlin/JVM port of the supplied plain HTTP socket streaming example. This is the
initial insecure baseline: cryptography and the secure handshake are not implemented yet.
The original Java files and study notes are under `reference/`.

## Requirements

- JDK 21 (build and runtime)
- Browser-compatible MP4 files, e.g. H.264 video and AAC audio

The Gradle Wrapper is included; no system Gradle installation is needed. Run all
commands below from the project root (the directory containing `gradlew`).

## Compile

```sh
./gradlew build
```

## Run locally

Put one or more MP4 files in `media/`. An empty directory is supported and the page
explains how to add files. The catalog lists MP4 files directly inside this directory.

Terminal 1 — Stream Server:

```sh
./gradlew run --args="server"
```

Terminal 2 — Proxy (same two-second delay per read as the Java reference):

```sh
./gradlew run --args="proxy"
```

Open http://localhost:8080/ and select a video. The page loads its metadata; press
Play to start playback. Refresh the list after adding files. The filename field
also permits manually requesting a file, as in the reference UI.

The reference delay limits throughput to at most about 512 bytes/second per video
connection. To observe normal playback, stop the proxy with Ctrl+C and run:

```sh
./gradlew run --args="proxy 8080 localhost 8081 0"
```

Both components are independent processes. Stop each with Ctrl+C.

### Alternative media directory

For the existing reference media directory:

```sh
./gradlew run --args="server 8081 reference/WA1-Materials/streamserver/media"
```

Paths are relative to the project root when using these Gradle commands. Paths
containing spaces must be quoted inside the `--args` value.

### IntelliJ

Run `ssc.MainKt` twice with program arguments `server` and `proxy` (or
`proxy 8080 localhost 8081 0`). Set the working directory to the project root and
allow multiple instances, or create separate Server and Proxy run configurations.

### Different machines

On the server machine, run `server 8081 /path/to/media`. On the proxy machine run
`proxy 8080 SERVER_HOST 8081 0`, replacing SERVER_HOST with the server's address.
Open `http://PROXY_HOST:8080/` in a browser. The machines must permit TCP access to
these ports. No TLS or authentication is present in this baseline.

## Behavior and small extensions

- The socket/thread-pool architecture, 1024-byte buffers, one request per
  connection, streaming without whole-file buffering, and HTTP Range support
  follow the reference. The original media I/O exception behavior is retained.
- `GET /catalog` lists URL-encoded MP4 filenames, one per line. The proxy relays
  this request to the server; it does not read the server's filesystem.
- The page displays a selector and retains the original manual filename field.
- Filename URL decoding supports spaces and accents in the selection.
- The fourth proxy argument adjusts the artificial delay; its default is 2000 ms.
- The server fails early with a clear error if its media directory does not exist.

## Quick checks

```sh
curl -i http://localhost:8080/catalog
curl -i http://localhost:8080/missing
curl -i -H 'Range: bytes=0-99' http://localhost:8080/video/sample.mp4
```

Expect an encoded filename list (200), a missing route (404), and a 100-byte
partial response (206) respectively, provided sample.mp4 exists and has at least
100 bytes. Inspect playback and seeking in the browser too.
