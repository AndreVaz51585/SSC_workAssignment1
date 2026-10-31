package ssc.protocol.handshake

import ssc.config.CryptoConfigLoader
import ssc.config.CryptoConfigValidator
import ssc.config.HandshakeConfigValidator
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.HexFormat

/** One-connection exercise of the real handshake. The existing HTTP video baseline remains separate. */
object HandshakeDemo {
    fun server(args: Array<String>) {
        val port = args.getOrNull(0)?.toInt() ?: 8082
        val path = args.getOrNull(1) ?: "config/sservercrypto.config" // obtem a path para o respetivo ficheiro de configuração

        // valida a logica da cipherSuite depois de transformada num dto validado
        val config = CryptoConfigValidator.validate(CryptoConfigLoader.load(path, "ServerCryptoConfig")) // chama primeiro o CryptoConfigLoader para carregar todos os campos e tags do xml e coloca-os num dto

        val settings = HandshakeConfigValidator.validate(config) // valida o perfil de handshake e a disponibilidade da suite AEAD escolhida

        ServerSocket(port).use { listener ->
            println("Handshake server listening on port $port (one session; no media transfer yet)")
            listener.accept().use { socket ->
                socket.soTimeout = settings.socketTimeoutMillis
                val session = ServerHandshake(config).perform(socket.getInputStream(), socket.getOutputStream())
                println("Types 1/2/3 validated. Requested media: ${session.media}")
                println("Session ID: ${HexFormat.of().formatHex(session.sessionId())}; keys are not printed")
            }
        }
    }

    fun proxy(args: Array<String>) {
        val host = args.getOrNull(0) ?: "localhost"
        val port = args.getOrNull(1)?.toInt() ?: 8082
        val media = args.getOrNull(2) ?: "sample.mp4"
        val path = args.getOrNull(3) ?: "config/proxycrypto.config"
        val config = CryptoConfigValidator.validate(CryptoConfigLoader.load(path, "ProxyCryptoConfig"))
        val settings = HandshakeConfigValidator.validate(config)
        Socket().use { socket ->
            socket.connect(InetSocketAddress(host, port), settings.socketTimeoutMillis)
            socket.soTimeout = settings.socketTimeoutMillis
            val session = ProxyHandshake(config).perform(socket.getInputStream(), socket.getOutputStream(), media)
            println("Type 2 authenticated; Type 3 sent. Server acceptance awaits protected media in the next increment.")
            println("Session ID: ${HexFormat.of().formatHex(session.sessionId())}; keys are not printed")
        }
    }
}
