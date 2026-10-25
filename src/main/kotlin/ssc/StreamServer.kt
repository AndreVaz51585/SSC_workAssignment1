package ssc

import java.io.IOException
import java.io.OutputStream
import java.io.RandomAccessFile
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.Executors

object StreamServer {
    private const val BLOCK_SIZE = 1024

    fun run(args: Array<String>) {
        val port = args.getOrNull(0)?.toInt() ?: 8081
        val root = Path.of(args.getOrNull(1) ?: "media").toAbsolutePath().normalize()
        require(Files.isDirectory(root)) { "Media directory does not exist: $root" }
        ServerSocket(port).use { server ->
            println("Stream server on http://localhost:$port/media/<file.mp4> (dir: $root)")
            val pool = Executors.newCachedThreadPool()
            try {
                while (true) {
                    val client = server.accept()
                    pool.submit { handle(client, root) }
                }
            } finally {
                pool.shutdown()
            }
        }
    }

    fun handle(socket: Socket, root: Path) {
        try {
            socket.use {
                val input = socket.getInputStream()
                val out = socket.getOutputStream()
                val requestLine = HttpUtil.readLine(input)
                if (requestLine == null || !requestLine.startsWith("GET ")) {
                    writeStatus(out, 400, "Bad Request", 0)
                    return
                }
                val path = requestLine.split(' ')[1]
                var rangeHeader: String? = null
                while (true) {
                    val line = HttpUtil.readLine(input) ?: break
                    if (line.isEmpty()) break
                    val c = line.indexOf(':')
                    if (c > 0 && line.substring(0, c).equals("Range", ignoreCase = true)) {
                        rangeHeader = line.substring(c + 1).trim()
                    }
                }
                // Extension: the server, which owns the media directory, provides the catalog.
                if (path == "/catalog") {
                    serveCatalog(out, root)
                    return
                }
                if (!path.startsWith("/media/")) {
                    writeStatus(out, 404, "Not Found", 0)
                    return
                }
                val name = try {
                    HttpUtil.decodeName(path.removePrefix("/media/"))
                } catch (_: IllegalArgumentException) {
                    writeStatus(out, 400, "Bad Request", 0)
                    return
                }
                val file = root.resolve(name).normalize()
                if (!file.startsWith(root) || !Files.isRegularFile(file)) {
                    writeStatus(out, 404, "Not Found", 0)
                    return
                }
                serveFile(out, file, rangeHeader)
            }
        } catch (_: IOException) {
            // The proxy may disconnect during seeking or playback cancellation.
        }
    }

    private fun serveCatalog(out: OutputStream, root: Path) {
        // One URL-encoded filename per line, including support for spaces and accents.
        val names = Files.list(root).use { files ->
            files.filter { Files.isRegularFile(it) && it.fileName.toString().endsWith(".mp4", true) }
                .map { it.fileName.toString() }.sorted().toList()
        }
        val body = names.joinToString("\n") { HttpUtil.encodeName(it) }.toByteArray(StandardCharsets.UTF_8)
        writeHeaders(out, 200, "OK", body.size.toLong(), "text/plain; charset=utf-8", "Cache-Control: no-store\r\n")
        out.write(body)
        out.flush()
    }

    fun serveFile(out: OutputStream, file: Path, rangeHeader: String?) {
        val size = Files.size(file)
        var start = 0L
        var end = size - 1
        var partial = false
        if (rangeHeader != null && rangeHeader.startsWith("bytes=") && !rangeHeader.contains(',')) {
            try {
                val parts = rangeHeader.substring(6).trim().split('-')
                var e = end
                val s: Long
                if (parts[0].isEmpty()) {
                    s = maxOf(0L, size - parts[1].toLong())
                } else {
                    s = parts[0].toLong()
                    if (parts.size > 1 && parts[1].isNotEmpty()) e = minOf(parts[1].toLong(), size - 1)
                }
                if (s > e || s >= size) {
                    writeHeaders(out, 416, "Range Not Satisfiable", 0, null, "Content-Range: bytes */$size\r\n")
                    return
                }
                start = s
                end = e
                partial = true
            } catch (_: NumberFormatException) {
                // Match the reference: malformed ranges fall back to the whole file.
            } catch (_: IndexOutOfBoundsException) {
            }
        }
        val length = end - start + 1
        val extraHeaders = "Accept-Ranges: bytes\r\n" +
            if (partial) "Content-Range: bytes $start-$end/$size\r\n" else ""
        writeHeaders(out, if (partial) 206 else 200, if (partial) "Partial Content" else "OK",
            length, "video/mp4", extraHeaders)
        RandomAccessFile(file.toFile(), "r").use { raf ->
            raf.seek(start)
            val block = ByteArray(BLOCK_SIZE)
            var remaining = length
            while (remaining > 0) {
                val n = raf.read(block, 0, minOf(block.size.toLong(), remaining).toInt())
                if (n < 0) break
                out.write(block, 0, n)
                out.flush()
                remaining -= n
            }
        }
    }

    fun writeStatus(out: OutputStream, code: Int, reason: String, contentLength: Long) =
        writeHeaders(out, code, reason, contentLength, null, null)

    fun writeHeaders(out: OutputStream, code: Int, reason: String, contentLength: Long,
                     contentType: String?, extraHeaders: String?) {
        val headers = buildString {
            append("HTTP/1.1 $code $reason\r\n")
            if (contentType != null) append("Content-Type: $contentType\r\n")
            append("Content-Length: $contentLength\r\nConnection: close\r\n")
            if (extraHeaders != null) append(extraHeaders)
            append("\r\n")
        }
        out.write(headers.toByteArray(StandardCharsets.US_ASCII))
        out.flush()
    }
}
