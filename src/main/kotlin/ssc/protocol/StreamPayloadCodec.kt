package ssc.protocol

import ssc.protocol.dto.EndStreamPayload
import ssc.protocol.dto.MediaResponseMetadata
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets

/** Type 4 encrypts METADATA or DATA; Type 5 encrypts SEQF || END || length || random ASCII string. */
object StreamPayloadCodec {
    const val SEQUENCE_BYTES = Long.SIZE_BYTES
    const val METADATA = 0
    const val DATA = 1
    private const val METADATA_BYTES = 1 + 2 + 1 + 8 * 4 + 1

    fun kind(plaintext: ByteArray): Int {
        require(plaintext.isNotEmpty()) { "Type 4 sem subtipo" }
        return plaintext[0].toInt() and 255
    }

    fun encodeMetadata(metadata: MediaResponseMetadata): ByteArray {
        metadata.validate()
        val contentType = when (metadata.contentType) {
            null -> 0
            MediaResponseMetadata.VIDEO_TYPE -> 1
            MediaResponseMetadata.CATALOG_TYPE -> 2
            else -> error("Content-Type não validado")
        }
        return ByteBuffer.allocate(METADATA_BYTES).put(METADATA.toByte()).putShort(metadata.statusCode.toShort())
            .put(contentType.toByte()).putLong(metadata.totalLength ?: -1).putLong(metadata.contentLength)
            .putLong(metadata.rangeStart ?: -1).putLong(metadata.rangeEndInclusive ?: -1)
            .put(if (metadata.acceptRanges) 1.toByte() else 0.toByte()).array()
    }

    fun decodeMetadata(plaintext: ByteArray): MediaResponseMetadata {
        require(plaintext.size == METADATA_BYTES && kind(plaintext) == METADATA) { "Metadados com formato inválido" }
        val bytes = ByteBuffer.wrap(plaintext)
        bytes.get()
        val status = bytes.short.toInt() and 65535
        val contentType = when (bytes.get().toInt()) {
            0 -> null
            1 -> MediaResponseMetadata.VIDEO_TYPE
            2 -> MediaResponseMetadata.CATALOG_TYPE
            else -> throw IllegalArgumentException("Código de Content-Type inválido")
        }
        fun optionalLong(): Long? = bytes.long.let {
            require(it >= -1) { "Metadado inteiro inválido" }
            if (it == -1L) null else it
        }
        val total = optionalLong()
        val length = bytes.long
        val start = optionalLong()
        val end = optionalLong()
        val acceptRanges = when (bytes.get().toInt()) {
            0 -> false
            1 -> true
            else -> throw IllegalArgumentException("Flag Accept-Ranges inválida")
        }
        return MediaResponseMetadata(status, contentType, total, length, start, end, acceptRanges).also { it.validate() }
    }

    fun encodeData(block: ByteArray): ByteArray {
        require(block.isNotEmpty()) { "Bloco de dados vazio" }
        return byteArrayOf(DATA.toByte()) + block
    }

    fun decodeData(plaintext: ByteArray): ByteArray {
        require(plaintext.size > 1 && kind(plaintext) == DATA) { "Bloco de dados inválido" }
        return plaintext.copyOfRange(1, plaintext.size)
    }

    private val endMarker = "END".toByteArray(StandardCharsets.US_ASCII)

    fun encodeSequence(sequence: Long): ByteArray {
        require(sequence >= 0) { "Sequência negativa" }
        return ByteBuffer.allocate(SEQUENCE_BYTES).putLong(sequence).array()
    }

    fun decodeSequence(bytes: ByteArray): Long {
        require(bytes.size >= SEQUENCE_BYTES) { "Sequência incompleta" }
        return ByteBuffer.wrap(bytes, 0, SEQUENCE_BYTES).long.also {
            require(it >= 0) { "Sequência negativa" }
        }
    }

    fun encodeEnd(end: EndStreamPayload, randomCharacters: Int): ByteArray {
        require(end.randomString.length == randomCharacters && end.randomString.all { it in "0123456789abcdef" }) {
            "Random STRING de END inválida"
        }
        val random = end.randomString.toByteArray(StandardCharsets.US_ASCII)
        return ByteBuffer.allocate(SEQUENCE_BYTES + endMarker.size + Int.SIZE_BYTES + random.size)
            .put(encodeSequence(end.sequence)).put(endMarker).putInt(random.size).put(random).array()
    }

    fun decodeEnd(plaintext: ByteArray, randomCharacters: Int): EndStreamPayload {
        val expectedSize = SEQUENCE_BYTES + endMarker.size + Int.SIZE_BYTES + randomCharacters
        require(plaintext.size == expectedSize) { "ENDBLOCK com tamanho inválido" }
        val bytes = ByteBuffer.wrap(plaintext)
        val sequence = bytes.long
        require(sequence >= 0) { "Sequência negativa" }
        val marker = ByteArray(endMarker.size).also { bytes.get(it) }
        require(marker.contentEquals(endMarker)) { "Marcador END inválido" }
        require(bytes.int == randomCharacters) { "Comprimento de Random STRING inválido" }
        val random = ByteArray(randomCharacters).also { bytes.get(it) }
        val end = EndStreamPayload(sequence, String(random, StandardCharsets.US_ASCII))
        // Check ASCII hex too; replacement characters must never be accepted as a valid string.
        encodeEnd(end, randomCharacters)
        return end
    }
}
