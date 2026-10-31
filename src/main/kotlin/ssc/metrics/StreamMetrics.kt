package ssc.metrics

import ssc.protocol.ProtocolMessageCodec
import ssc.protocol.dto.MediaResponseMetadata
import ssc.protocol.dto.MessageType
import ssc.protocol.dto.ProtocolMessage
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.util.Locale

/** One receiver owns this accumulator; there is no shared counter between connections. */
class StreamMetrics(private val nanoTime: () -> Long = System::nanoTime) {
    private var startedAt: Long? = null
    private var description: MediaResponseMetadata? = null
    private var frames = 0L
    private var type4Frames = 0L
    private var recordBytes = 0L
    private var encryptedBlocks = 0L
    private var encryptedPayloadBytes = 0L
    private var decryptedBytes = 0L
    private var forwardedBlocks = 0L
    private var forwardedBytes = 0L
    var result: StreamMetricsSnapshot? = null
        private set

    internal fun start() {
        check(startedAt == null) { "Métricas não podem ser reutilizadas entre transferências" }
        startedAt = nanoTime()
    }

    internal fun received(frame: ProtocolMessage) {
        frames++
        if (frame.header.message == MessageType.MEDIA_BLOCK) type4Frames++
        recordBytes += ProtocolMessageCodec.HEADER_SIZE + frame.payload.size.toLong()
    }

    internal fun metadata(value: MediaResponseMetadata) { description = value }

    /** DATA is identifiable only after authentication; metadata is not a media block. */
    internal fun decrypted(frame: ProtocolMessage, bytes: Int) {
        encryptedBlocks++
        encryptedPayloadBytes += frame.payload.size
        decryptedBytes += bytes
    }

    /** Count only writes whose write and flush both returned successfully. */
    internal fun forwarded(bytes: Int) {
        forwardedBlocks++
        forwardedBytes += bytes
    }

    internal fun finish(completed: Boolean) {
        val elapsed = (nanoTime() - requireNotNull(startedAt)).coerceAtLeast(0)
        result = StreamMetricsSnapshot(completed, elapsed, description, frames, type4Frames,
            recordBytes, encryptedBlocks, encryptedPayloadBytes, decryptedBytes, forwardedBlocks, forwardedBytes)
    }
}

/** Frozen at completion/abort, so formatting a log cannot extend the measured duration. */
data class StreamMetricsSnapshot(
    val completed: Boolean,
    val elapsedNanos: Long,
    val metadata: MediaResponseMetadata?,
    val completeFramesReceived: Long,
    val type4FramesReceived: Long,
    val recordBytesReceived: Long,
    val encryptedMediaBlocksReceived: Long,
    val encryptedMediaPayloadBytes: Long,
    val decryptedMediaBytes: Long,
    val forwardedMediaBlocks: Long,
    val forwardedMediaBytes: Long,
) {
    // Decimal kB/s. Includes origin reads, authentication/decryption and browser writes; excludes handshake.
    val throughputKBps: Double
        get() = if (elapsedNanos == 0L) 0.0 else forwardedMediaBytes * 1_000_000.0 / elapsedNanos

    /** Default terminal view. Detailed, exact counters remain available through toLogLine(). */
    fun toSummary(resource: String, failure: String? = null): String {
        fun safe(value: String) = value.replace("\\", "\\\\").replace("\"", "\\\"")
            .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
            .map { if (it.isISOControl()) '?' else it }.joinToString("")
        fun number(value: Double) = String.format(Locale.ROOT, "%.2f", value)
        fun amount(bytes: Long?): String = when {
            bytes == null -> "?"
            bytes < 1000 -> "$bytes B"
            bytes < 1_000_000 -> "${number(bytes / 1000.0)} kB"
            else -> "${number(bytes / 1_000_000.0)} MB"
        }
        val status = when {
            !completed -> "INTERROMPIDO"
            (metadata?.statusCode ?: 0) >= 400 -> "HTTP ${metadata?.statusCode}"
            else -> "OK"
        }
        val reason = failure?.let { " | motivo: ${safe(it.take(160))}" } ?: ""
        return "[STREAM $status] \"${safe(resource)}\" | HTTP ${metadata?.statusCode ?: "?"}" +
            " | enviados ${amount(forwardedMediaBytes)}/${amount(metadata?.contentLength)}" +
            " (original ${amount(metadata?.totalLength)})$reason\n" +
            "  blocos autenticados/encaminhados: $encryptedMediaBlocksReceived/$forwardedMediaBlocks" +
            " | protocolo: ${amount(recordBytesReceived)} | ${number(elapsedNanos / 1_000_000.0)} ms" +
            " | ${number(throughputKBps / 1000)} MB/s"
    }

    fun toLogLine(requestId: String, resource: String, suite: String, keyBits: Int, mac: String?): String {
        fun number(value: Double) = String.format(Locale.ROOT, "%.3f", value)
        fun text(value: String) = URLEncoder.encode(value, StandardCharsets.UTF_8)
        return listOf(
            "event=stream_metrics", "requestId=${text(requestId)}", "resource=${text(resource)}",
            "suite=${text(suite)}", "keyBits=$keyBits", "mac=${mac?.let(::text) ?: "none"}",
            "transfer=${if (completed) "complete" else "aborted"}", "httpStatus=${metadata?.statusCode ?: "unknown"}",
            "originalBytes=${metadata?.totalLength ?: "unknown"}", "expectedBodyBytes=${metadata?.contentLength ?: "unknown"}",
            "rangeStart=${metadata?.rangeStart ?: "none"}", "rangeEnd=${metadata?.rangeEndInclusive ?: "none"}",
            "completeFramesReceived=$completeFramesReceived", "type4FramesReceived=$type4FramesReceived",
            "recordBytesReceived=$recordBytesReceived", "encryptedMediaBlocksReceived=$encryptedMediaBlocksReceived",
            "encryptedMediaPayloadBytes=$encryptedMediaPayloadBytes", "decryptedMediaBytes=$decryptedMediaBytes",
            "forwardedMediaBlocks=$forwardedMediaBlocks", "forwardedMediaBytes=$forwardedMediaBytes",
            "elapsedMs=${number(elapsedNanos / 1_000_000.0)}", "throughputKBps=${number(throughputKBps)}",
        ).joinToString(" ")
    }
}
