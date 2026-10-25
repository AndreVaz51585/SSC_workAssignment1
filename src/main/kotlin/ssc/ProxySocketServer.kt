package ssc

import java.io.IOException
import java.io.OutputStream
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.Executors

object ProxySocketServer {
    private const val BLOCK_SIZE = 1024
    private val INDEX_HTML = """
        <!doctype html>
        <html lang="pt"><head><meta charset="utf-8"><title>MP4 via socket-only proxy</title></head>
        <body style="font-family:sans-serif;max-width:900px;margin:2rem auto">
          <h1>MP4 streamed through a plain-socket proxy</h1>
          <p><label>Vídeos disponíveis: <select id="catalog" disabled></select></label>
             <button id="refresh" type="button">Atualizar lista</button></p>
          <p id="status" role="status">A carregar a lista de vídeos…</p>
          <p><label>Ficheiro: <input id="f" value="sample.mp4"></label>
             <button id="load" type="button">Carregar</button></p>
          <video id="v" controls preload="metadata" style="width:100%"></video>
          <script>
            function load() {
              const v = document.getElementById('v');
              v.src = '/video/' + encodeURIComponent(document.getElementById('f').value);
              v.load();
            }
            async function refresh(initial = false) {
              const select = document.getElementById('catalog');
              const status = document.getElementById('status');
              try {
                const response = await fetch('/catalog', {cache: 'no-store'});
                if (!response.ok) throw new Error('HTTP ' + response.status);
                const body = await response.text();
                const names = body ? body.split('\n').map(decodeURIComponent) : [];
                select.replaceChildren();
                for (const name of names) {
                  const option = document.createElement('option');
                  option.value = name;
                  option.textContent = name;
                  select.append(option);
                }
                select.disabled = names.length === 0;
                status.textContent = names.length ? names.length + ' vídeo(s) disponível(is).' :
                  'Sem MP4 disponíveis. Coloca ficheiros na pasta media do servidor e atualiza a lista.';
                const input = document.getElementById('f');
                if (names.includes(input.value)) select.value = input.value;
                else if (names.length) input.value = select.value;
                if (initial && names.length) load();
              } catch (error) {
                status.textContent = 'Não foi possível obter a lista. Verifica se o Stream Server está ligado.';
              }
            }
            document.getElementById('catalog').addEventListener('change', event => {
              document.getElementById('f').value = event.target.value;
              load();
            });
            document.getElementById('load').addEventListener('click', load);
            document.getElementById('refresh').addEventListener('click', () => refresh());
            refresh(true);
          </script>
        </body></html>
    """.trimIndent()

    fun run(args: Array<String>) {
        val port = args.getOrNull(0)?.toInt() ?: 8080
        val originHost = args.getOrNull(1) ?: "localhost"
        val originPort = args.getOrNull(2)?.toInt() ?: 8081
        // The default preserves the Java reference; use 0 for normal playback.
        val delayMillis = args.getOrNull(3)?.toLong() ?: 2000L
        require(delayMillis >= 0) { "Delay must be non-negative" }
        ServerSocket(port).use { server ->
            println("Proxy on http://localhost:$port/ -> http://$originHost:$originPort (delay: $delayMillis ms/read)")
            val pool = Executors.newCachedThreadPool()
            try {
                while (true) {
                    val client = server.accept()
                    pool.submit { handle(client, originHost, originPort, delayMillis) }
                }
            } finally {
                pool.shutdown()
            }
        }
    }

    fun handle(browser: Socket, originHost: String, originPort: Int, delayMillis: Long = 2000) {
        try {
            browser.use {
                val input = browser.getInputStream()
                val out = browser.getOutputStream()
                val requestLine = HttpUtil.readLine(input)
                if (requestLine == null || !requestLine.startsWith("GET ")) {
                    writeSimpleStatus(out, 400, "Bad Request")
                    return
                }
                val path = requestLine.split(' ')[1]
                var rangeHeader: String? = null
                while (true) {
                    val line = HttpUtil.readLine(input) ?: break
                    if (line.isEmpty()) break
                    val c = line.indexOf(':')
                    if (c > 0 && line.substring(0, c).equals("Range", true)) {
                        rangeHeader = line.substring(c + 1).trim()
                    }
                }
                if (path == "/" || path.isEmpty()) {
                    servePage(out)
                    return
                }
                if (path == "/catalog") {
                    // Catalog traffic follows the proxy too; no artificial media delay.
                    try {
                        relayResponse(out, originHost, originPort, "/catalog", null, 0)
                    } catch (_: IOException) {
                        writeSimpleStatus(out, 502, "Bad Gateway")
                    }
                    return
                }
                if (!path.startsWith("/video/")) {
                    writeSimpleStatus(out, 404, "Not Found")
                    return
                }
                relayFromOrigin(out, originHost, originPort, path.removePrefix("/video/"), rangeHeader, delayMillis)
            }
        } catch (_: IOException) {
            // Preserve the reference handling of disconnections and media connection failures.
        }
    }

    fun servePage(out: OutputStream) {
        val page = INDEX_HTML.toByteArray(StandardCharsets.UTF_8)
        val headers = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n" +
            "Content-Length: ${page.size}\r\nConnection: close\r\n\r\n"
        out.write(headers.toByteArray(StandardCharsets.US_ASCII))
        out.write(page)
        out.flush()
    }

    fun relayFromOrigin(browserOut: OutputStream, originHost: String, originPort: Int,
                        name: String, rangeHeader: String?, delayMillis: Long = 2000) =
        relayResponse(browserOut, originHost, originPort, "/media/$name", rangeHeader, delayMillis)

    private fun relayResponse(browserOut: OutputStream, originHost: String, originPort: Int,
                              path: String, rangeHeader: String?, delayMillis: Long) {
        Socket(originHost, originPort).use { origin ->
            val originOut = origin.getOutputStream()
            val originIn = origin.getInputStream()
            val request = buildString {
                append("GET $path HTTP/1.1\r\nHost: $originHost:$originPort\r\n")
                if (rangeHeader != null) append("Range: $rangeHeader\r\n")
                append("Connection: close\r\n\r\n")
            }
            originOut.write(request.toByteArray(StandardCharsets.US_ASCII))
            originOut.flush()
            val statusLine = HttpUtil.readLine(originIn)
            if (statusLine == null) {
                writeSimpleStatus(browserOut, 502, "Bad Gateway")
                return
            }
            val parts = statusLine.split(' ', limit = 3)
            val code = parts[1].toInt()
            val reason = parts.getOrElse(2) { "" }
            var contentLength = -1L
            var contentType: String? = null
            var contentRange: String? = null
            var acceptRanges: String? = null
            while (true) {
                val line = HttpUtil.readLine(originIn) ?: break
                if (line.isEmpty()) break
                val c = line.indexOf(':')
                if (c <= 0) continue
                val value = line.substring(c + 1).trim()
                when (line.substring(0, c).trim().lowercase()) {
                    "content-length" -> contentLength = value.toLong()
                    "content-type" -> contentType = value
                    "content-range" -> contentRange = value
                    "accept-ranges" -> acceptRanges = value
                }
            }
            val response = buildString {
                append("HTTP/1.1 $code $reason\r\n")
                if (contentType != null) append("Content-Type: $contentType\r\n")
                if (acceptRanges != null) append("Accept-Ranges: $acceptRanges\r\n")
                if (contentRange != null) append("Content-Range: $contentRange\r\n")
                if (contentLength >= 0) append("Content-Length: $contentLength\r\n")
                append("Connection: close\r\n\r\n")
            }
            browserOut.write(response.toByteArray(StandardCharsets.US_ASCII))
            browserOut.flush()
            if (contentLength <= 0) return
            val buffer = ByteArray(BLOCK_SIZE)
            var remaining = contentLength
            while (remaining > 0) {
                val n = originIn.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
                if (n < 0) break
                try {
                    Thread.sleep(delayMillis)
                } catch (_: InterruptedException) {
                    println("uppps")
                }
                browserOut.write(buffer, 0, n)
                browserOut.flush()
                remaining -= n
            }
        }
    }

    fun writeSimpleStatus(out: OutputStream, code: Int, reason: String) {
        val response = "HTTP/1.1 $code $reason\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        out.write(response.toByteArray(StandardCharsets.US_ASCII))
        out.flush()
    }
}
