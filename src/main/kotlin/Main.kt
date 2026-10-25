package ssc

fun main(args: Array<String>) {
    when (args.firstOrNull()) {
        "server" -> StreamServer.run(args.drop(1).toTypedArray())
        "proxy" -> ProxySocketServer.run(args.drop(1).toTypedArray())
        else -> println("""
            Usage:
              server [port=8081] [mediaDir=media]
              proxy [port=8080] [originHost=localhost] [originPort=8081] [delayMillis=2000]
            Start each component in a separate process. Open http://localhost:8080/ in your browser.
        """.trimIndent())
    }
}
