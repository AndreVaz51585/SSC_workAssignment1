package ssc

import ssc.config.CryptoConfigLoader
import ssc.config.CryptoConfigValidator
import ssc.config.HandshakeConfigValidator
import ssc.config.ValidatedCryptoConfig
import ssc.media.SecureMediaSource
import ssc.protocol.handshake.ServerHandshake
import ssc.protocol.stream.SecureStreamSender
import java.net.ServerSocket
import java.net.Socket
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.Executors

/** Concurrent secure origin. Browser HTTP terminates at the proxy, never on this socket. */
object SecureStreamServer {
    fun run(args: Array<String>) {
        val port = args.getOrNull(0)?.toInt() ?: 8082
        val root = Path.of(args.getOrNull(1) ?: "media").toRealPath()
        require(Files.isDirectory(root)) { "Diretoria de media inválida" }
        val path = args.getOrNull(2) ?: "config/sservercrypto.config"
        val config = CryptoConfigValidator.validate(CryptoConfigLoader.load(path, "ServerCryptoConfig"))
        HandshakeConfigValidator.validate(config)
        ServerSocket(port).use { server ->
            println("Secure stream server on port $port (media: $root; suite=${config.suite}; keyBits=${config.config.keySizeBits})")
            val pool = Executors.newCachedThreadPool()
            try {
                while (true) {
                    val socket = server.accept()
                    pool.submit { handle(socket, root, config) }
                }
            } finally { pool.shutdownNow() }
        }
    }

    fun handle(socket: Socket, root: Path, config: ValidatedCryptoConfig) {
        socket.use {
            try {
                val settings = HandshakeConfigValidator.validate(config)
                socket.soTimeout = settings.socketTimeoutMillis
                val output = socket.getOutputStream()
                val session = ServerHandshake(config).perform(socket.getInputStream(), output)
                SecureMediaSource.open(root, session.media, session.rangeHeader).use { response ->
                    SecureStreamSender(session, settings).send(response.body, output, response.metadata)
                }
            } catch (exception: Exception) {
                // Browser seeks can cancel an old request; never reuse that session/socket afterwards.
                System.err.println("Secure stream connection closed: ${exception.message}")
            }
        }
    }
}
