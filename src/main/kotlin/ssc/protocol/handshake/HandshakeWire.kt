package ssc.protocol.handshake

import ssc.config.ValidatedCryptoConfig
import ssc.config.dto.HandshakeConfig
import ssc.protocol.ProtocolMessageCodec
import ssc.protocol.dto.MessageHeader
import ssc.protocol.dto.MessageType
import ssc.protocol.dto.ProposedCryptoConfig
import ssc.protocol.dto.ProtocolMessage
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.net.ProtocolException

internal object HandshakeWire {
    fun proposal(config: ValidatedCryptoConfig, settings: HandshakeConfig) = ProposedCryptoConfig(
        config.suite.algorithm, config.suite.mode, config.suite.ivSizeBits, null,
        config.config.keySizeBits, config.macSuite?.configName, config.config.macKeySizeBits,
        settings.dhGroup, settings.kdf, settings.authentication, settings.tagSizeBits, settings.randomSizeBytes,
    )

    fun bytes(message: ProtocolMessage): ByteArray = ProtocolMessageCodec.encodeHeader(message.header) + message.payload

    fun frame(type: MessageType, payload: ByteArray) = ProtocolMessage(
        MessageHeader(message = type, payloadLength = payload.size), payload,
    )

    // Interpreta o envelope da mensagem, ou seja os 9bytes enviados (2 bytes Version, 2 bytes Release, 1 Byte Type e 4 bytes payloadLength)
    // garante que está correto e é o expectavél e transforma tudo num objeto com os dados todos separados
    fun read(input: InputStream, expected: MessageType, maximum: Int): ProtocolMessage {
        val frame = ProtocolMessageCodec.read(input, maximum) ?: throw EOFException("Ligação terminada durante o handshake")
        if (frame.header.message == MessageType.ERROR_ALERT) throw ProtocolException("O outro participante abortou o handshake")
        require(frame.header.version == 1 && frame.header.release == 1) { "Versão de protocolo incompatível" }
        require(frame.header.message == expected) { "Mensagem inesperada no estado atual do handshake" }
        return frame
    }

    fun send(output: OutputStream, frame: ProtocolMessage, maximum: Int) {
        require(frame.payload.size <= maximum) { "Mensagem excede o limite local" }
        ProtocolMessageCodec.write(output, frame)
    }

    fun alert(output: OutputStream) {
        // A pre-session alert cannot always be authenticated. It is diagnostic only:
        // never trust its reason, downgrade algorithms or retry with weaker settings.
        runCatching {
            ProtocolMessageCodec.write(output, frame(MessageType.ERROR_ALERT,
                "Handshake failed".toByteArray(Charsets.UTF_8)))
        }
    }

    fun validateRange(rangeHeader: String?) {
        require(rangeHeader == null || (rangeHeader.length in 1..1024 && rangeHeader.all { it.code in 32..126 })) {
            "Range deve ser texto ASCII limitado, sem caracteres de controlo"
        }
    }

    fun validateMedia(media: String) {
        require(media.isNotBlank() && media.toByteArray(Charsets.UTF_8).size <= 1024 &&
            media.none { it == '\r' || it == '\n' || it == '\u0000' }) { "Nome de media inválido" }
    }
}
