package ssc

import ssc.protocol.handshake.HandshakeDemo
import ssc.protocol.stream.SecureStreamDemo

// tudo começa aqui desde que corremos o comando por exemplo ./gradlew run --args="handshake-proxy localhost 8082 sintel.mp4"
// aqui os argumentos são handshake-proxy localhost 8082 sintel.mp4



fun main(args: Array<String>) {
    when (args.firstOrNull()) {
        "handshake-server", "handshake-proxy", "secure-stream-server", "secure-stream-proxy", "secure-server", "secure-proxy" -> { // escolhe o papel e o exercício
            try {
                val arguments = args.drop(1).toTypedArray() // remove o primeiro argumento
                when (args[0]) {
                    "secure-server" -> SecureStreamServer.run(arguments)
                    "secure-proxy" -> SecureProxyServer.run(arguments)
                    "handshake-server" -> HandshakeDemo.server(arguments)
                    "handshake-proxy" -> HandshakeDemo.proxy(arguments)
                    "secure-stream-server" -> SecureStreamDemo.server(arguments)
                    "secure-stream-proxy" -> SecureStreamDemo.proxy(arguments)
                }
            } catch (exception: Exception) {
                System.err.println("Secure protocol failed: ${exception.message}")
                kotlin.system.exitProcess(1)
            }
        }
        "server" -> StreamServer.run(args.drop(1).toTypedArray())
        "proxy" -> ProxySocketServer.run(args.drop(1).toTypedArray())
        else -> println("""
            Usage:
              server [port=8081] [mediaDir=media]
              proxy [port=8080] [originHost=localhost] [originPort=8081] [delayMillis=2000]
              handshake-server [port=8082] [config=config/sservercrypto.config]
              handshake-proxy [host=localhost] [port=8082] [media=sample.mp4] [config=config/proxycrypto.config]
              secure-stream-server [port=8082] [mediaDir=media] [config=config/sservercrypto.config]
              secure-stream-proxy [host=localhost] [port=8082] [media=sample.mp4] [destination=received.mp4] [config=config/proxycrypto.config]
              secure-server [port=8082] [mediaDir=media] [config=config/sservercrypto.config]
              secure-proxy [port=8080] [originHost=localhost] [originPort=8082] [config=config/proxycrypto.config]
            The handshake commands are a separate test; server/proxy still run the plaintext video baseline.
            Start each component in a separate process. Open http://localhost:8080/ in your browser.
        """.trimIndent())
    }
}
