package ssc.protocol

import ssc.protocol.dto.MessageHeader
import ssc.protocol.dto.MessageType
import ssc.protocol.dto.ProtocolMessage
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.net.ProtocolException
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Binary framing only: message authentication and handshake state belong to later layers. */
object ProtocolMessageCodec {
    const val HEADER_SIZE = 9 // version(2) + release(2) + type(1) + payloadLength(4)

    fun write(output: OutputStream, message: ProtocolMessage) {
        require(message.header.payloadLength == message.payload.size) {
            "PayloadLength deve corresponder ao número de bytes do payload"
        }
        output.write(encodeHeader(message.header))
        output.write(message.payload)
        output.flush()
    }

    /** The exact header bytes are also used as authenticated associated data (AAD). */
    fun encodeHeader(header: MessageHeader): ByteArray {
        require(header.version in 0..0xFFFF) { "Version deve caber em 2 bytes sem sinal" }
        require(header.release in 0..0xFFFF) { "Release deve caber em 2 bytes sem sinal" }
        require(header.payloadLength >= 0) { "PayloadLength não pode ser negativo" }
        val bytes = java.io.ByteArrayOutputStream(HEADER_SIZE)
        val data = DataOutputStream(bytes)
        data.writeShort(header.version)
        data.writeShort(header.release)
        data.writeByte(header.message.code)
        data.writeInt(header.payloadLength)
        return bytes.toByteArray()
    }

    fun read(input: InputStream, maxPayloadLength: Int): ProtocolMessage? {
        require(maxPayloadLength >= 0) { "MaxPayloadLength não pode ser negativo" }

        // readNBytes accumulates fragmented reads until 9 bytes or end-of-stream.
        val headerBytes = input.readNBytes(HEADER_SIZE)

        if (headerBytes.isEmpty()) return null // Clean EOF between complete messages.

        // se o tamanho for diferente de 9 bytes
        if (headerBytes.size != HEADER_SIZE) {
            throw EOFException("Cabeçalho incompleto: esperados $HEADER_SIZE bytes, recebidos ${headerBytes.size}")
        }

        val buffer = ByteBuffer.wrap(headerBytes).order(ByteOrder.BIG_ENDIAN)
        val version = buffer.short.toInt() and 0xFFFF
        val release = buffer.short.toInt() and 0xFFFF
        val typeCode = buffer.get().toInt() and 0xFF
        val type = MessageType.entries.singleOrNull { it.code == typeCode }
            ?: throw ProtocolException("Tipo de mensagem desconhecido: $typeCode")
        val payloadLength = buffer.int

        // Validate the untrusted length BEFORE allocating the payload buffer.
        if (payloadLength < 0 || payloadLength > maxPayloadLength) {
            throw ProtocolException("Tamanho do payload fora do limite permitido: $payloadLength")
        }
        val payload = ByteArray(payloadLength)
        // readFully either fills the buffer or throws EOFException: no partial message is accepted.
        DataInputStream(input).readFully(payload)

        return ProtocolMessage(
            header = MessageHeader(
                version = version,
                release = release,
                message = type,
                payloadLength = payloadLength,
            ),
            payload = payload,
        )
    }
}
