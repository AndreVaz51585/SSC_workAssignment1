package ssc.support

import ssc.HttpUtil
import ssc.SecureProxyServer
import ssc.SecureStreamServer
import ssc.config.CryptoConfigLoader
import ssc.config.CryptoConfigValidator
import ssc.config.HandshakeConfigValidator
import ssc.config.ValidatedCryptoConfig
import ssc.media.SecureMediaSource
import ssc.protocol.handshake.HandshakeSession
import ssc.protocol.handshake.ProxyHandshake
import ssc.protocol.handshake.ServerHandshake
import ssc.protocol.stream.SecureStreamSender
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Shared test plumbing only; the real protocol classes process every handshake/record. */
internal object ProtocolTestSupport {
    private fun config() = CryptoConfigValidator.validate(
        CryptoConfigLoader.load("src/test/resources/config/proxycrypto.config"))

    data class HandshakeOutcome(val proxy: Result<HandshakeSession>, val server: Result<HandshakeSession>)

    /** Transform a complete serialized frame at flush boundaries to model an active network attacker. */
    private class FrameFilter(private val target: OutputStream, private val transform: (ByteArray) -> ByteArray) : OutputStream() {
        private val pending = ByteArrayOutputStream()
        override fun write(value: Int) { pending.write(value) }
        override fun write(bytes: ByteArray, offset: Int, length: Int) { pending.write(bytes, offset, length) }
        override fun flush() {
            if (pending.size() > 0) {
                target.write(transform(pending.toByteArray()))
                pending.reset()
            }
            target.flush()
        }
    }

    fun exchangeHandshake(
        proxyConfig: ValidatedCryptoConfig = config(),
        serverConfig: ValidatedCryptoConfig = config(),
        proxyFrames: (ByteArray) -> ByteArray = { it },
        serverFrames: (ByteArray) -> ByteArray = { it },
    ): HandshakeOutcome {
        val pool = Executors.newSingleThreadExecutor()
        try {
            ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { listener ->
                val server = pool.submit(Callable {
                    runCatching {
                        listener.accept().use { socket ->
                            socket.soTimeout = 3000
                            ServerHandshake(serverConfig).perform(socket.getInputStream(), FrameFilter(socket.getOutputStream(), serverFrames))
                        }
                    }
                })
                val proxy = runCatching {
                    Socket(InetAddress.getLoopbackAddress(), listener.localPort).use { socket ->
                        socket.soTimeout = 3000
                        ProxyHandshake(proxyConfig).perform(socket.getInputStream(), FrameFilter(socket.getOutputStream(), proxyFrames), "música.mp4")
                    }
                }
                return HandshakeOutcome(proxy, server.get(5, TimeUnit.SECONDS))
            }
        } finally {
            pool.shutdownNow()
        }
    }

    data class HttpResponse(val status: Int, val headers: Map<String, String>, val body: ByteArray)

    /** Actual HTTP -> proxy -> authenticated handshake -> encrypted origin response, on ephemeral ports. */
    fun withHttpServers(change: ((ByteArray) -> ByteArray)? = null,
                        profile: String = "aes256-gcm", originProfile: String = profile,
                        action: (Int, Path, ByteArray) -> Unit) {
        val root = Files.createTempDirectory("secure-http-test-").toRealPath()
        val data = ByteArray(16397) { (it * 31).toByte() }
        Files.write(root.resolve("sample.mp4"), data)
        Files.write(root.resolve("música de teste.mp4"), data)
        Files.write(root.resolve("empty.mp4"), byteArrayOf())
        val config = CryptoConfigValidator.validate(CryptoConfigLoader.load(
            "src/test/resources/config/profiles/$profile/proxy.config", "ProxyCryptoConfig"))
        val serverConfig = CryptoConfigValidator.validate(CryptoConfigLoader.load(
            "src/test/resources/config/profiles/$originProfile/server.config", "ServerCryptoConfig"))
        val settings = HandshakeConfigValidator.validate(serverConfig)
        val pool = Executors.newCachedThreadPool()
        val origin = ServerSocket(0, 50, InetAddress.getLoopbackAddress())
        val proxy = ServerSocket(0, 50, InetAddress.getLoopbackAddress())
        fun accept(listener: ServerSocket, handler: (Socket) -> Unit) = pool.submit {
            while (!listener.isClosed) {
                try {
                    val client = listener.accept()
                    pool.submit { handler(client) }
                } catch (exception: SocketException) {
                    if (!listener.isClosed) throw exception
                }
            }
        }
        accept(origin) { socket ->
            if (change == null) SecureStreamServer.handle(socket, root, serverConfig)
            else socket.use {
                socket.soTimeout = 3000
                val output = FrameFilter(socket.getOutputStream(), change)
                val session = ServerHandshake(serverConfig).perform(socket.getInputStream(), output)
                SecureMediaSource.open(root, session.media, session.rangeHeader).use { response ->
                    SecureStreamSender(session, settings).send(response.body, output, response.metadata)
                }
            }
        }
        accept(proxy) { SecureProxyServer.handle(it, "localhost", origin.localPort, config) }
        try {
            action(proxy.localPort, root, data)
        } finally {
            proxy.close()
            origin.close()
            pool.shutdown()
            if (!pool.awaitTermination(5, TimeUnit.SECONDS)) pool.shutdownNow()
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) } }
        }
    }

    fun get(port: Int, path: String, vararg headers: String): HttpResponse {
        Socket(InetAddress.getLoopbackAddress(), port).use { socket ->
            socket.soTimeout = 5000
            val request = "GET $path HTTP/1.1\r\nHost: localhost\r\n" +
                headers.joinToString("") { "$it\r\n" } + "Connection: close\r\n\r\n"
            socket.getOutputStream().write(request.toByteArray(Charsets.US_ASCII))
            val input = socket.getInputStream()
            val status = requireNotNull(HttpUtil.readLine(input)).split(' ')[1].toInt()
            val responseHeaders = mutableMapOf<String, String>()
            while (true) {
                val line = requireNotNull(HttpUtil.readLine(input))
                if (line.isEmpty()) break
                responseHeaders[line.substringBefore(':').lowercase()] = line.substringAfter(':').trim()
            }
            val length = requireNotNull(responseHeaders["content-length"]).toInt()
            // HTTP is delimited by Content-Length, not by an extra read after a zero-length response.
            return HttpResponse(status, responseHeaders, input.readNBytes(length))
        }
    }

}
