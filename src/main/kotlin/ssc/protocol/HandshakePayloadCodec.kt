package ssc.protocol

import ssc.protocol.dto.ClientFinishedPayload
import ssc.protocol.dto.ClientHelloPayload
import ssc.protocol.dto.ProposedCryptoConfig
import ssc.protocol.dto.ServerHelloPayload
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction

/** Canonical binary payloads. No Java serialization, JSON or local XML (which contains secrets). */


/***
 *
 * Objeto responsavél por escrever em Bytes o conteudo dos payloads e para depois os reconstruir.
 *
 */
object HandshakePayloadCodec {
    private const val HMAC_BYTES = 32 // HMAC-SHA256, the only authentication profile currently implemented.
    private const val MAX_STRING_BYTES = 1024
    private const val MAX_PUBLIC_KEY_BYTES = 1024

    // Type 1's HMAC is calculated over this body and its final message header, not over itself.

    // Escrevem no mesmo buffer, pela ordem indicada, consoante o conteudo de cada.
    fun encodeClientHelloBody(hello: ClientHelloPayload): ByteArray = encode {
        writeLong(hello.sequence)
        writeConfig(hello.proposedConfig)
        writeFixed(hello.clientRandom, hello.proposedConfig.randomSizeBytes)
        writeSized(hello.dhPublicKey)
    }

    fun encodeClientHello(hello: ClientHelloPayload): ByteArray {
        require(hello.authenticationTag.size == HMAC_BYTES) { "Tag HMAC inválida" }
        return encodeClientHelloBody(hello) + hello.authenticationTag
    }

    fun decodeClientHello(payload: ByteArray, randomBytes: Int): ClientHelloPayload {
        require(payload.size >= HMAC_BYTES) { "ClientHello incompleto" }
        val body = payload.copyOfRange(0, payload.size - HMAC_BYTES)
        val tag = payload.copyOfRange(payload.size - HMAC_BYTES, payload.size)
        return decode(body) {
            val sequence = readLong()
            val config = readConfig()
            require(config.randomSizeBytes == randomBytes) { "Tamanho aleatório incompatível" }
            val clientRandom = readFixed(randomBytes)
            val publicKey = readSized(MAX_PUBLIC_KEY_BYTES)
            ClientHelloPayload(sequence, config, publicKey, clientRandom, tag)
        }
    }

    // Helpers do not store parsing state; this explicit decoder mirrors Type 2's SEQY || SRV || CCC.
    fun encodeServerHello(hello: ServerHelloPayload): ByteArray = encode {
        writeLong(hello.seqy)
        writeFixed(hello.srv, hello.acceptedConfig.randomSizeBytes)
        writeConfig(hello.acceptedConfig)
        writeSized(hello.dhPublicKey)
    }

    fun decodeServerHello(payload: ByteArray, randomBytes: Int): ServerHelloPayload = decode(payload) {
        val sequence = readLong()
        val challenge = readFixed(randomBytes)
        val config = readConfig()
        require(config.randomSizeBytes == randomBytes) { "Tamanho aleatório incompatível" }
        ServerHelloPayload(challenge, sequence, config, readSized(MAX_PUBLIC_KEY_BYTES))
    }

    fun encodeClientFinished(finished: ClientFinishedPayload): ByteArray = encode {
        writeLong(finished.sequence)
        writeFixed(finished.challengeResponse, HMAC_BYTES) // SHA256(SRV), not an independent proof of identity.
        writeText(finished.media)
        writeByte(if (finished.rangeHeader == null) 0 else 1)
        finished.rangeHeader?.let { writeText(it) }
    }

    fun decodeClientFinished(payload: ByteArray): ClientFinishedPayload = decode(payload) {
        val sequence = readLong()
        val response = readFixed(HMAC_BYTES)
        val media = readText()
        val range = when (readUnsignedByte()) {
            0 -> null
            1 -> readText()
            else -> throw IllegalArgumentException("Flag de Range inválida")
        }
        ClientFinishedPayload(sequence, response, media, range)
    }


    // Função responsavél por escrever a proposta criptográfica numa sequencia de bytes
    private fun DataOutputStream.writeConfig(config: ProposedCryptoConfig) {
        // Keep the assignment's PCC/CCC reference string as the first configuration field.
        writeText("${config.algorithm}/${config.mode}/NULL/${config.padding ?: "NULL"}") // está a indicar IV null, mas não significa que não vamos usar IV, mas sim que não deve fixo.
        writeInt(config.ivSizeBits) // Int ocupa sempre 4 Bytes
        writeInt(config.keySizeBits)
        writeText(config.macAlgorithm ?: "NULL")
        writeInt(config.macKeySizeBits ?: -1)
        // Public extensions needed to bind the authenticated key agreement to the proposal.
        writeText(config.dhGroup)
        writeText(config.kdf)
        writeText(config.handshakeAuthentication)
        writeInt(config.tagSizeBits)
        writeInt(config.randomSizeBytes)
    }

    private fun DataInputStream.readConfig(): ProposedCryptoConfig {
        val parts = readText().split('/')
        require(parts.size == 4 && parts[2] == "NULL") { "PCC/CCC inválido ou IV fixo não permitido" }
        val ivBits = readInt()
        val keyBits = readInt()
        val mac = readText().takeUnless { it == "NULL" }
        val macBits = readInt().let { if (it == -1) null else it }
        return ProposedCryptoConfig(parts[0], parts[1], ivBits, parts[3].takeUnless { it == "NULL" },
            keyBits, mac, macBits, readText(), readText(), readText(), readInt(), readInt())
    }

    /**
     *  Constroi um array de bytes em memória
     * */
    private fun encode(write: DataOutputStream.() -> Unit): ByteArray = ByteArrayOutputStream().let { bytes -> // o byte array cria um buffer onde vão ser acumulados os bytes escritos
        DataOutputStream(bytes).use { write.invoke(it) } // dentro deste buffer, conseguimos escrever tanto Int como Long en formato binário
        bytes.toByteArray()  // devolve os bytes acumulados.
    }

    private fun <T> decode(bytes: ByteArray, read: DataInputStream.() -> T): T {
        val input = DataInputStream(bytes.inputStream())
        val result = read.invoke(input)
        require(input.available() == 0) { "Bytes adicionais no fim do payload" }
        return result
    }

    private fun DataOutputStream.writeText(value: String) {
        val bytes = value.toByteArray(Charsets.UTF_8)
        require(bytes.size in 1..MAX_STRING_BYTES) { "String vazia ou demasiado grande" }
        writeSized(bytes)
    }

    private fun DataInputStream.readText(): String = Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(readSized(MAX_STRING_BYTES))).toString()

    private fun DataOutputStream.writeSized(bytes: ByteArray) {
        require(bytes.size in 1..MAX_PUBLIC_KEY_BYTES) { "Campo binário vazio ou demasiado grande" }
        writeInt(bytes.size)
        write(bytes)
    }

    private fun DataInputStream.readSized(maximum: Int): ByteArray {
        val length = readInt()
        require(length in 1..maximum && length <= available()) { "Comprimento de campo inválido" }
        return readFixed(length)
    }

    private fun DataOutputStream.writeFixed(bytes: ByteArray, expectedSize: Int) {
        require(bytes.size == expectedSize) { "Campo binário com tamanho inesperado" }
        write(bytes)
    }

    private fun DataInputStream.readFixed(length: Int): ByteArray {
        require(length >= 0 && length <= available()) { "Campo binário incompleto" }
        return ByteArray(length).also { readFully(it) }
    }
}
