package ssc.protocol.stream

import ssc.config.dto.HandshakeConfig
import ssc.protocol.ProtocolMessageCodec
import ssc.protocol.StreamPayloadCodec
import ssc.protocol.dto.EndStreamPayload
import ssc.protocol.dto.MediaBlockPayload
import ssc.protocol.dto.MediaResponseMetadata
import ssc.protocol.dto.MessageType
import ssc.protocol.handshake.HandshakeSession
import java.io.InputStream
import java.io.EOFException
import java.io.OutputStream
import java.security.SecureRandom
import java.util.HexFormat

/** One sender per session. Caller owns/closes streams, and must abort the connection on failure. */
class SecureStreamSender(session: HandshakeSession, private val settings: HandshakeConfig) {
    private val protection = StreamRecordProtection(session, settings)
    private var started = false

    init { session.claimStreamSender() }

    fun send(media: InputStream, output: OutputStream, metadata: MediaResponseMetadata, blockSize: Int = 1024): Long {
        check(!started) { "Uma sessão não pode reiniciar a transmissão nem reutilizar nonces" }
        started = true // Also prevents retrying this sender after a failed write.
        try {
            metadata.validate()
            require(blockSize in 1 until protection.maximumBlockBytes) { "BlockSize excede o limite de payload" }
            val blocks = metadata.contentLength / blockSize + if (metadata.contentLength % blockSize == 0L) 0 else 1
            require(blocks <= settings.maxStreamRecords - 2) { "Resposta excede MaxStreamRecords" }
            var sequence = protection.firstSequence
            sendMetadata(output, sequence++, metadata)
            var remaining = metadata.contentLength
            val buffer = ByteArray(blockSize)
            while (remaining > 0) {
                val count = media.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
                if (count < 0) throw EOFException("Media terminou antes do comprimento anunciado")
                if (count == 0) continue
                sendBlock(output, MediaBlockPayload(sequence, buffer.copyOf(count)))
                sequence++
                remaining -= count
            }
            sendEnd(output, sequence)
            return metadata.contentLength
        } finally {
            protection.destroy()
        }
    }

    private fun sendMetadata(output: OutputStream, sequence: Long, metadata: MediaResponseMetadata) {
        val plaintext = StreamPayloadCodec.encodeMetadata(metadata)
        ProtocolMessageCodec.write(output, protection.protect(MessageType.MEDIA_BLOCK, sequence, plaintext))
    }

    private fun sendBlock(output: OutputStream, block: MediaBlockPayload) {
        val frame = protection.protect(block.messageType, block.sequence, StreamPayloadCodec.encodeData(block.block))
        ProtocolMessageCodec.write(output, frame)
    }

    private fun sendEnd(output: OutputStream, sequence: Long) {
        val random = ByteArray(settings.randomSizeBytes).also { SecureRandom().nextBytes(it) }
        val end = EndStreamPayload(sequence, HexFormat.of().formatHex(random))
        val plaintext = StreamPayloadCodec.encodeEnd(end, settings.randomSizeBytes * 2)
        val frame = protection.protect(MessageType.END_STREAM, sequence, plaintext)
        ProtocolMessageCodec.write(output, frame)
    }
}
