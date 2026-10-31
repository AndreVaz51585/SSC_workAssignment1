package ssc.protocol.stream

import ssc.config.dto.HandshakeConfig
import ssc.crypto.MessageProtection
import ssc.protocol.ProtocolMessageCodec
import ssc.protocol.StreamPayloadCodec
import ssc.protocol.dto.MessageHeader
import ssc.protocol.dto.MessageType
import ssc.protocol.dto.ProtocolMessage
import ssc.protocol.handshake.HandshakeSession

/** Used by one sender or one receiver for this session's server -> proxy direction. */
internal class StreamRecordProtection(session: HandshakeSession, private val settings: HandshakeConfig) {
    private val cipher = MessageProtection(session.suite, settings.tagSizeBits, session.macSuite, (session.keys.serverToProxy.macKey?.sizeBits ?: 0) / 8)
    private val key = session.keys.serverToProxy.key.copyBytes() // chave do trafego derivada do final do handshake
    private val macKey = session.keys.serverToProxy.macKey?.copyBytes()
    private val baseIv = session.keys.serverToProxy.iv.copyBytes()
    private val sessionId = session.sessionId()
    val firstSequence = session.firstMediaSequence
    val maximumBlockBytes = settings.maxPayloadBytes - StreamPayloadCodec.SEQUENCE_BYTES - settings.tagSizeBits / 8

    init {
        require(baseIv.size == cipher.ivBytes) { "Base de nonce incompatível com a suite da sessão" }
        require(firstSequence >= 0 && maximumBlockBytes > 0) { "Parâmetros de registos inválidos" }
        require(settings.randomSizeBytes == 32) { "Este perfil exige aleatórios de 32 bytes" }
        require(settings.maxPayloadBytes in 2048..1048576) { "Limite de payload inválido" }
        require(settings.maxStreamRecords in 1..MAX_RECORDS) { "Limite de registos inválido" }
    }

    fun protect(type: MessageType, sequence: Long, plaintext: ByteArray): ProtocolMessage {
        validateSequence(sequence)
        require(type == MessageType.MEDIA_BLOCK || type == MessageType.END_STREAM) { "Tipo de registo inválido" }
        require(plaintext.size <= maximumBlockBytes) { "Bloco excede MaxPayloadBytes" }
        val sequenceBytes = StreamPayloadCodec.encodeSequence(sequence)
        val header = MessageHeader(message = type,
            payloadLength = sequenceBytes.size + plaintext.size + settings.tagSizeBits / 8)
        val aad = ProtocolMessageCodec.encodeHeader(header) + sequenceBytes + sessionId
        val encrypted = cipher.encrypt(plaintext, key, nonce(sequence), aad, macKey)
        return ProtocolMessage(header, sequenceBytes + encrypted)
    }

    fun unprotect(frame: ProtocolMessage, expectedSequence: Long): ByteArray {
        validateSequence(expectedSequence)
        require(frame.header.version == 1 && frame.header.release == 1) { "Versão de registo incompatível" }
        require(frame.header.message == MessageType.MEDIA_BLOCK || frame.header.message == MessageType.END_STREAM) {
            "Esperado Type 4 ou Type 5; transmissão abortada"
        }
        require(frame.header.payloadLength == frame.payload.size && frame.payload.size <= settings.maxPayloadBytes) {
            "Comprimento de registo inválido"
        }
        require(frame.payload.size >= StreamPayloadCodec.SEQUENCE_BYTES + settings.tagSizeBits / 8) { "Registo incompleto" }
        val sequence = StreamPayloadCodec.decodeSequence(frame.payload)
        require(sequence == expectedSequence) { "Sequência inesperada: bloco repetido, em falta ou fora de ordem" }
        val sequenceBytes = frame.payload.copyOfRange(0, StreamPayloadCodec.SEQUENCE_BYTES)
        val encrypted = frame.payload.copyOfRange(StreamPayloadCodec.SEQUENCE_BYTES, frame.payload.size)
        val aad = ProtocolMessageCodec.encodeHeader(frame.header) + sequenceBytes + sessionId
        return cipher.decrypt(encrypted, key, nonce(sequence), aad, macKey)
    }

    private fun validateSequence(sequence: Long) {
        require(sequence >= firstSequence && sequence - firstSequence < settings.maxStreamRecords && sequence < Long.MAX_VALUE) {
            "Limite de registos atingido: estabelecer uma nova sessão"
        }
    }

    /** AEAD: unique nonce; CTR: separate prefix and per-message counter domain. */
    internal fun nonce(sequence: Long): ByteArray = cipher.nonce(baseIv, sequence)

    fun destroy() { key.fill(0); baseIv.fill(0); macKey?.fill(0) }

    companion object {
        // Protocol ceiling, not permission to run indefinitely under one traffic key. No counter wrap.
        internal const val MAX_RECORDS = 1L shl 32
    }
}
