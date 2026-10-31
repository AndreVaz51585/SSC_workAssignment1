package ssc.protocol.stream

import ssc.config.dto.HandshakeConfig
import ssc.metrics.StreamMetrics
import ssc.protocol.ProtocolMessageCodec
import ssc.protocol.StreamPayloadCodec
import ssc.protocol.dto.MediaResponseMetadata
import ssc.protocol.dto.MessageType
import ssc.protocol.handshake.HandshakeSession
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream

/** First verify metadata, then data. Keep only the last block pending until authenticated END. */
class SecureStreamReceiver(session: HandshakeSession, private val settings: HandshakeConfig,
                           private val metrics: StreamMetrics = StreamMetrics()) {
    private val protection = StreamRecordProtection(session, settings)
    private var started = false

    init { session.claimStreamReceiver() }

    fun receive(input: InputStream, media: OutputStream, onMetadata: (MediaResponseMetadata) -> Unit = {}): Long {
        check(!started) { "Uma sessão não pode reiniciar a receção" }
        started = true
        metrics.start()
        var completed = false
        try {
            var sequence = protection.firstSequence
            var metadata: MediaResponseMetadata? = null
            var totalBytes = 0L
            var pendingBlock: ByteArray? = null
            while (true) {
                val frame = ProtocolMessageCodec.read(input, settings.maxPayloadBytes)
                    ?: throw EOFException("Ligação terminada sem Type 5 autenticado: transmissão incompleta")
                metrics.received(frame)
                val plaintext = protection.unprotect(frame, sequence)
                when (frame.header.message) {
                    MessageType.MEDIA_BLOCK -> {
                        when (StreamPayloadCodec.kind(plaintext)) {
                            StreamPayloadCodec.METADATA -> {
                                require(metadata == null) { "Metadados repetidos ou fora de ordem" }
                                metadata = StreamPayloadCodec.decodeMetadata(plaintext)
                                metrics.metadata(metadata)
                                onMetadata(metadata)
                            }
                            StreamPayloadCodec.DATA -> {
                                val description = requireNotNull(metadata) { "Dados antes dos metadados" }
                                val block = StreamPayloadCodec.decodeData(plaintext)
                                require(block.size.toLong() <= description.contentLength - totalBytes) { "Dados excedem Content-Length autenticado" }
                                metrics.decrypted(frame, block.size)
                                // The new block is already authenticated; a failed write of the previous
                                // block leaves both counted as received but not successfully forwarded.
                                pendingBlock?.let { receiveBlock(media, it) }
                                pendingBlock = block
                                totalBytes += block.size
                            }
                            else -> throw IllegalArgumentException("Subtipo Type 4 desconhecido")
                        }
                        sequence++
                    }
                    MessageType.END_STREAM -> {
                        val description = requireNotNull(metadata) { "END antes dos metadados" }
                        receiveEnd(plaintext, sequence)
                        require(totalBytes == description.contentLength) { "END antes do comprimento anunciado" }
                        // In HTTP, do not let Content-Length look complete before END is authenticated.
                        pendingBlock?.let { receiveBlock(media, it) }
                        media.flush()
                        completed = true
                        return totalBytes
                    }
                    else -> error("Tipo já deveria ter sido rejeitado pela proteção do registo")
                }
            }
        } finally {
            metrics.finish(completed)
            protection.destroy()
        }
    }

    private fun receiveBlock(media: OutputStream, block: ByteArray) {
        media.write(block)
        media.flush()
        metrics.forwarded(block.size)
    }

    private fun receiveEnd(plaintext: ByteArray, expectedSequence: Long) {
        val end = StreamPayloadCodec.decodeEnd(plaintext, settings.randomSizeBytes * 2)
        require(end.sequence == expectedSequence) { "Sequência interior de ENDBLOCK inválida" }
    }
}
