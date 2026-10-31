package ssc

import ssc.config.CryptoConfigLoader
import ssc.config.CryptoConfigValidator
import ssc.config.HandshakeConfigValidator
import ssc.config.ValidatedCryptoConfig
import ssc.media.SecureMediaSource
import ssc.metrics.StreamMetrics
import ssc.protocol.dto.MediaResponseMetadata
import ssc.protocol.handshake.HandshakeWire
import ssc.protocol.handshake.ProxyHandshake
import ssc.protocol.stream.SecureStreamReceiver
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors
import java.util.UUID

/** One browser GET -> one fresh authenticated origin connection -> one protected response. */
object SecureProxyServer {
    private val detailedMetrics = System.getenv("METRICS_FORMAT").equals("detailed", ignoreCase = true)
    private data class BrowserRequest(val path: String, val rangeHeader: String?)

    fun run(args: Array<String>) {
        val port = args.getOrNull(0)?.toInt() ?: 8080
        val host = args.getOrNull(1) ?: "localhost"
        val originPort = args.getOrNull(2)?.toInt() ?: 8082
        val path = args.getOrNull(3) ?: "config/proxycrypto.config"
        val config = CryptoConfigValidator.validate(CryptoConfigLoader.load(path, "ProxyCryptoConfig"))
        HandshakeConfigValidator.validate(config)
        ServerSocket(port).use { server ->
            println("Secure proxy on http://localhost:$port/ -> $host:$originPort (suite=${config.suite}; keyBits=${config.config.keySizeBits})")
            val pool = Executors.newCachedThreadPool()
            try {
                while (true) {
                    val socket = server.accept()
                    pool.submit { handle(socket, host, originPort, config) }
                }
            } finally { pool.shutdownNow() }
        }
    }

    fun handle(browser: Socket, host: String, originPort: Int, config: ValidatedCryptoConfig) {
        browser.use {
            browser.soTimeout = HandshakeConfigValidator.validate(config).socketTimeoutMillis
            val output = browser.getOutputStream()
            val request = try {
                readRequest(browser.getInputStream())
            } catch (_: Exception) {
                runCatching { ProxySocketServer.writeSimpleStatus(output, 400, "Bad Request") }
                return
            } ?: return // A connection closed before its first request is not an origin request.
            when {
                request.path == "/" -> ProxySocketServer.servePage(output)
                request.path == "/catalog" -> relayResponse(output, host, originPort, config, SecureMediaSource.CATALOG, null)
                request.path.startsWith("/video/") -> {
                    val media = try {
                        HttpUtil.decodeName(request.path.removePrefix("/video/"))
                            .also { HandshakeWire.validateMedia(it) }
                    } catch (_: IllegalArgumentException) {
                        ProxySocketServer.writeSimpleStatus(output, 400, "Bad Request")
                        return
                    }
                    // Reserve /catalog for the catalog route, not an encoded video filename.
                    if (media == SecureMediaSource.CATALOG) {
                        ProxySocketServer.writeSimpleStatus(output, 404, "Not Found")
                        return
                    }
                    relayResponse(output, host, originPort, config, media, request.rangeHeader)
                }
                else -> ProxySocketServer.writeSimpleStatus(output, 404, "Not Found")
            }
        }
    }

    private fun readRequest(input: InputStream): BrowserRequest? {
        val line = HttpUtil.readLine(input) ?: return null
        val parts = line.split(' ')
        require(parts.size == 3 && parts[0] == "GET" && parts[2] in setOf("HTTP/1.1", "HTTP/1.0"))
        require(parts[1].startsWith('/') && parts[1].all { it.code in 33..126 })
        var range: String? = null
        var bytes = line.length
        var count = 0
        var ifRange = false
        while (true) {
            val header = requireNotNull(HttpUtil.readLine(input)) { "Pedido HTTP incompleto" }
            if (header.isEmpty()) break
            bytes += header.length
            require(++count <= 100 && bytes <= 65536) { "Headers HTTP demasiado grandes" }
            val colon = header.indexOf(':')
            require(colon > 0)
            val name = header.substring(0, colon)
            val value = header.substring(colon + 1).trim()
            require(name.all { it.isLetterOrDigit() || it == '-' })
            require(value.all { it.code in 32..126 || it == '\t' })
            if (name.equals("Range", true)) {
                require(range == null) { "Range repetido" }
                HandshakeWire.validateRange(value)
                range = value
            }
            if (name.equals("If-Range", true)) ifRange = true
        }
        // No ETag/Last-Modified validators in this increment: conservatively send full content.
        return BrowserRequest(parts[1].substringBefore('?'), if (ifRange) null else range)
    }

    private fun relayResponse(output: OutputStream, host: String, port: Int, config: ValidatedCryptoConfig,
                              media: String, range: String?) {
        val settings = HandshakeConfigValidator.validate(config)
        var headersStarted = false
        val metrics = StreamMetrics()
        var failure: Exception? = null
        try {
            Socket().use { origin ->
                origin.connect(InetSocketAddress(host, port), settings.socketTimeoutMillis)
                origin.soTimeout = settings.socketTimeoutMillis
                val session = ProxyHandshake(config).perform(origin.getInputStream(), origin.getOutputStream(), media, range)
                SecureStreamReceiver(session, settings, metrics).receive(origin.getInputStream(), output) { metadata ->
                    headersStarted = true
                    writeHeaders(output, metadata)
                }
            }
        } catch (exception: Exception) {
            // Once headers/body started, close this HTTP response; never append a second status line.
            if (!headersStarted) runCatching { ProxySocketServer.writeSimpleStatus(output, 502, "Bad Gateway") }
            failure = exception
        } finally {
            val result = metrics.result
            // Stream failures appear once in the summary; handshake failures have no metrics snapshot.
            if (result == null || detailedMetrics)
                failure?.let { System.err.println("Secure proxy response aborted: ${it.message}") }
            if (result != null) {
                if (detailedMetrics) {
                    println(result.toLogLine(UUID.randomUUID().toString(), media, config.suite.name,
                        config.config.keySizeBits, config.macSuite?.configName))
                } else if (media != SecureMediaSource.CATALOG || !result.completed || result.metadata?.statusCode != 200) {
                    // Catalog success is routine UI traffic. Keep errors visible.
                    println(result.toSummary(media, failure?.message))
                }
            }
        }
    }

    private fun writeHeaders(output: OutputStream, metadata: MediaResponseMetadata) {
        metadata.validate()
        val reason = when (metadata.statusCode) {
            200 -> "OK"
            206 -> "Partial Content"
            400 -> "Bad Request"
            404 -> "Not Found"
            416 -> "Range Not Satisfiable"
            else -> error("Estado já deveria estar validado")
        }
        val extra = buildString {
            if (metadata.acceptRanges) append("Accept-Ranges: bytes\r\n")
            if (metadata.statusCode == 206)
                append("Content-Range: bytes ${metadata.rangeStart}-${metadata.rangeEndInclusive}/${metadata.totalLength}\r\n")
            if (metadata.statusCode == 416) append("Content-Range: bytes */${metadata.totalLength}\r\n")
            append("Cache-Control: no-store\r\n")
        }
        StreamServer.writeHeaders(output, metadata.statusCode, reason, metadata.contentLength, metadata.contentType, extra)
        output.flush()
    }
}
