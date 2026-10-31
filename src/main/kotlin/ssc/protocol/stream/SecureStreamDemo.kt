package ssc.protocol.stream

import ssc.config.CryptoConfigLoader
import ssc.config.CryptoConfigValidator
import ssc.config.HandshakeConfigValidator
import ssc.media.SecureMediaSource
import ssc.protocol.handshake.ProxyHandshake
import ssc.protocol.handshake.ServerHandshake
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption

/** One-shot file transfer using the same protected response format as the browser service. */
object SecureStreamDemo {
    fun server(args: Array<String>) {
        val port = args.getOrNull(0)?.toInt() ?: 8082
        val root = Path.of(args.getOrNull(1) ?: "media").toRealPath()
        require(Files.isDirectory(root)) { "Diretoria de media inválida" }
        val path = args.getOrNull(2) ?: "config/sservercrypto.config"
        val config = CryptoConfigValidator.validate(CryptoConfigLoader.load(path, "ServerCryptoConfig"))
        val settings = HandshakeConfigValidator.validate(config)
        ServerSocket(port).use { listener ->
            println("Secure stream server listening on port $port (one session)")
            listener.accept().use { socket ->
                socket.soTimeout = settings.socketTimeoutMillis
                val output = socket.getOutputStream()
                val session = ServerHandshake(config).perform(socket.getInputStream(), output)
                val bytes = SecureMediaSource.open(root, session.media, session.rangeHeader).use { response ->
                    SecureStreamSender(session, settings).send(response.body, output, response.metadata)
                }
                println("Sent $bytes media bytes; authenticated Type 5 sent.")
            }
        }
    }

    fun proxy(args: Array<String>) {
        val host = args.getOrNull(0) ?: "localhost"
        val port = args.getOrNull(1)?.toInt() ?: 8082
        val media = args.getOrNull(2) ?: "sample.mp4"
        val destination = Path.of(args.getOrNull(3) ?: "received.mp4").toAbsolutePath()
        val path = args.getOrNull(4) ?: "config/proxycrypto.config"
        val config = CryptoConfigValidator.validate(CryptoConfigLoader.load(path, "ProxyCryptoConfig"))
        val settings = HandshakeConfigValidator.validate(config)
        require(!Files.exists(destination)) { "O ficheiro de destino já existe; escolhe outro nome" }
        Socket().use { socket ->
            socket.connect(InetSocketAddress(host, port), settings.socketTimeoutMillis)
            socket.soTimeout = settings.socketTimeoutMillis
            val input = socket.getInputStream()
            val session = ProxyHandshake(config).perform(input, socket.getOutputStream(), media)
            // CREATE_NEW also protects against an existing file appearing after the check above.
            val output = Files.newOutputStream(destination, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
            try {
                val bytes = output.use { SecureStreamReceiver(session, settings).receive(input, it) { metadata ->
                    require(metadata.statusCode == 200) { "Media não disponível: HTTP ${metadata.statusCode}" }
                } }
                println("Received $bytes verified media bytes; authenticated Type 5 accepted.")
                println("Saved to $destination")
            } catch (exception: Exception) {
                Files.deleteIfExists(destination) // Never leave an incomplete transfer marked as successful.
                throw exception
            }
        }
    }
}
