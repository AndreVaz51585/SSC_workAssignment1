import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import java.lang.Thread;

/**
 * Proxy implemented with raw sockets only (java.net.ServerSocket / Socket), no
 * com.sun.net.httpserver, no java.net.http.HttpClient, no external libraries.
 * Serves a small page at "/" and relays GET /video/<file> to the origin server,
 * forwarding the Range header and streaming the response body back block by
 * block (no whole-file buffering). Each browser connection handles one request,
 * then closes.
 *
 * Usage: java ProxySocketServer [port=8080] [originHost=localhost] [originPort=8081]
 */
public class ProxySocketServer {

    static final int BLOCK_SIZE = 1024;

    static final String INDEX_HTML = """
            <!doctype html>
            <html><head><meta charset="utf-8"><title>MP4 via socket-only proxy</title></head>
            <body style="font-family:sans-serif;max-width:900px;margin:2rem auto">
              <h1>MP4 streamed through a plain-socket proxy</h1>
              <p>File: <input id="f" value="sample.mp4">
                 <button onclick="load()">Load</button></p>
              <video id="v" controls preload="metadata" style="width:100%"></video>
              <script>
                function load() {
                  const v = document.getElementById('v');
                  v.src = '/video/' + encodeURIComponent(document.getElementById('f').value);
                  v.load();
                }
                load();
              </script>
            </body></html>
            """;

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8080; // porta onde o proxy está à escuta
        String originHost = args.length > 1 ? args[1] : "localhost"; // host do stream server
        int originPort = args.length > 2 ? Integer.parseInt(args[2]) : 8081; // porta do stream server

        try (ServerSocket server = new ServerSocket(port)) { // inicia o socket em (https://localhost:8080)
            System.out.println("Proxy on http://localhost:" + port + "/  ->  http://" + originHost + ":" + originPort);
            var pool = Executors.newCachedThreadPool(); // cria uma thread pool para dar handle a multiplos clientes
            while (true) {
                Socket client = server.accept(); // aceita a conexão do cliente browser -> localhost:8080
                pool.submit(() -> handle(client, originHost, originPort)); // cria uma nova thread para a ligação
            }
        }
    }


    /*
    * Função responsavél por atender o pedido do browser por exemplo:
    * GET / -> serverPage(out) entrega a pagina html ao browser
    * GET video/sample.mp4 HTTP/1.1 -> chama relayFromOrigin() para obter e reencaminhar o video.
    * GET /outro -> envia 404 not found
    * GET qualquer coisa -> 404 not found
    * */
    static void handle(Socket browser, String originHost, int originPort) {
        try (browser) {
            InputStream in = browser.getInputStream();  // input do browser
            OutputStream out = browser.getOutputStream(); // output para o browser

            String requestLine = HttpUtil.readLine(in); // lê uma linha do input
            if (requestLine == null || !requestLine.startsWith("GET ")) { // se o pedido não for um get ou estiver vazio -> 400 bad request
                writeSimpleStatus(out, 400, "Bad Request");
                return;
            }

            String path = requestLine.split(" ")[1]; // pega na path do pedido /video , etc

            String rangeHeader = null;
            String line;

            // continua a ler o input do socket isto é para pedir uma determinada range.
            while ((line = HttpUtil.readLine(in)) != null && !line.isEmpty()) {
                int c = line.indexOf(':');
                if (c > 0 && line.substring(0, c).equalsIgnoreCase("Range")) {
                    rangeHeader = line.substring(c + 1).trim(); // pega na range
                }
            }

            // se path for / -> serve o html
            if (path.equals("/") || path.isEmpty()) {
                servePage(out);
                return;
            }
            // existem duas opções ou / ou /video qualquer outro é 404 not found
            if (!path.startsWith("/video/")) {
                writeSimpleStatus(out, 404, "Not Found");
                return;
            }

            String name = path.substring("/video/".length()); // vai buscar o nome do video
            relayFromOrigin(out, originHost, originPort, name, rangeHeader);

        } catch (IOException e) {
            // Browser disconnected or origin unreachable mid-stream: nothing to do.
        }
    }


    // função responsavél por servir o html, converte o em bytes e envia-o ao browser.
    static void servePage(OutputStream out) throws IOException {
        byte[] page = INDEX_HTML.getBytes(StandardCharsets.UTF_8);
        StringBuilder headers = new StringBuilder();
        headers.append("HTTP/1.1 200 OK\r\n")
                .append("Content-Type: text/html; charset=utf-8\r\n")
                .append("Content-Length: ").append(page.length).append("\r\n")
                .append("Connection: close\r\n\r\n");
        out.write(headers.toString().getBytes(StandardCharsets.US_ASCII));
        out.write(page);
        out.flush();
    }


    // função responsavél por pedir o video ao stream server.
    static void relayFromOrigin(OutputStream browserOut, String originHost, int originPort,
                                 String name, String rangeHeader) throws IOException {

        // liga-se ao socket do stream-server : http://localhost:8081
        try (Socket origin = new Socket(originHost, originPort)) {
            OutputStream originOut = origin.getOutputStream(); // output vindo do stream-server
            InputStream originIn = origin.getInputStream(); // input do proxy -> stream-server

            StringBuilder req = new StringBuilder();

            // envia o pedido ao stream-server
            req.append("GET /media/").append(name).append(" HTTP/1.1\r\n")
                    .append("Host: ").append(originHost).append(":").append(originPort).append("\r\n");

            // define a range do pedido
            if (rangeHeader != null) req.append("Range: ").append(rangeHeader).append("\r\n");

            // fecha a conexão
            req.append("Connection: close\r\n\r\n");
            originOut.write(req.toString().getBytes(StandardCharsets.US_ASCII));
            originOut.flush();

            // Parse the origin's status line + headers
            // erro na conexão do socket ao server
            String statusLine = HttpUtil.readLine(originIn);
            if (statusLine == null) {
                writeSimpleStatus(browserOut, 502, "Bad Gateway");
                return;
            }
            String[] parts = statusLine.split(" ", 3);
            int code = Integer.parseInt(parts[1]);
            String reason = parts.length > 2 ? parts[2] : "";


            // Lê a resposta do stream-server para a passar ao browser diretamente

            long contentLength = -1;
            String contentType = null, contentRange = null, acceptRanges = null;
            String line;
            while ((line = HttpUtil.readLine(originIn)) != null && !line.isEmpty()) {
                int c = line.indexOf(':');
                if (c <= 0) continue;
                String h = line.substring(0, c).trim();
                String v = line.substring(c + 1).trim();
                switch (h.toLowerCase()) {
                    case "content-length" -> contentLength = Long.parseLong(v);
                    case "content-type" -> contentType = v;
                    case "content-range" -> contentRange = v;
                    case "accept-ranges" -> acceptRanges = v;
                }
            }

            // constroi a resposta para o browser
            // a range existe caso o browser decida escoher um determinado ponto do video etc.
            // Forward status + the headers the browser needs for playback/seeking
            StringBuilder resp = new StringBuilder();
            resp.append("HTTP/1.1 ").append(code).append(' ').append(reason).append("\r\n");
            if (contentType != null) resp.append("Content-Type: ").append(contentType).append("\r\n");
            if (acceptRanges != null) resp.append("Accept-Ranges: ").append(acceptRanges).append("\r\n");
            if (contentRange != null) resp.append("Content-Range: ").append(contentRange).append("\r\n");
            if (contentLength >= 0) resp.append("Content-Length: ").append(contentLength).append("\r\n");
            resp.append("Connection: close\r\n\r\n");
            browserOut.write(resp.toString().getBytes(StandardCharsets.US_ASCII));
            browserOut.flush();

            if (contentLength <= 0) return;

            // Relay the body block by block; closing either socket cancels the transfer.
            byte[] buf = new byte[BLOCK_SIZE];
            long remaining = contentLength;
            while (remaining > 0) {
                int n = originIn.read(buf, 0, (int) Math.min(buf.length, remaining));
                if (n < 0) break;
		try{
		    Thread.sleep(2000);
		    // can you push for the minimum required to
		    // mainain good buffering and playout delay maintaining
		    // a good vizualization-playing experience ?
		} catch (InterruptedException e) {
		    System.out.println("uppps");
		}
		    
                browserOut.write(buf, 0, n);
                browserOut.flush();
                remaining -= n;
            }
        }
    }

    static void writeSimpleStatus(OutputStream out, int code, String reason) throws IOException {
        String resp = "HTTP/1.1 " + code + " " + reason + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        out.write(resp.getBytes(StandardCharsets.US_ASCII));
        out.flush();
    }
}
