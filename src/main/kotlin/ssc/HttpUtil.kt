package ssc

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.IOException
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

object HttpUtil {
    // Read only through CRLF, leaving binary body bytes untouched.
    fun readLine(input: InputStream, maxLength: Int = 8192): String? {
        val line = ByteArrayOutputStream()
        var previous = -1
        while (true) {
            val current = input.read()
            if (current == -1) break
            if (previous == '\r'.code && current == '\n'.code) {
                val bytes = line.toByteArray()
                return String(bytes, 0, bytes.size - 1, StandardCharsets.US_ASCII)
            }
            if (line.size() >= maxLength) throw IOException("Linha HTTP demasiado longa")
            line.write(current)
            previous = current
        }
        return if (line.size() == 0) null else line.toString(StandardCharsets.US_ASCII)
    }

    fun encodeName(name: String): String =
        URLEncoder.encode(name, StandardCharsets.UTF_8).replace("+", "%20")

    fun decodeName(name: String): String =
        URLDecoder.decode(name.replace("+", "%2B"), StandardCharsets.UTF_8)
}
