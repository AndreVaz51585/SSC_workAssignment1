package ssc.protocol.handshake

import ssc.config.HandshakeConfigValidator
import ssc.config.ValidatedCryptoConfig
import ssc.crypto.DiffieHellmanSession
import ssc.crypto.MessageProtection
import ssc.crypto.HandshakeCrypto
import ssc.crypto.HandshakeKeySchedule
import ssc.protocol.HandshakePayloadCodec
import ssc.protocol.ProtocolMessageCodec
import ssc.protocol.dto.ClientFinishedPayload
import ssc.protocol.dto.ClientHelloPayload
import ssc.protocol.dto.MessageType
import ssc.protocol.dto.ProtocolMessage
import ssc.protocol.dto.ServerHelloPayload
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom

class ProxyHandshake(private val config: ValidatedCryptoConfig) {
    private val settings = HandshakeConfigValidator.validate(config)
    private val keyBytes = config.config.keySizeBits / 8
    private val cipher = MessageProtection(config.suite, settings.tagSizeBits, config.macSuite, (config.config.macKeySizeBits ?: 0) / 8)

    /** Caller owns the connection and must close it on failure; one invocation per connection. */
    fun perform(input: InputStream, output: OutputStream, media: String, rangeHeader: String? = null): HandshakeSession {
        try {
            HandshakeWire.validateMedia(media)
            HandshakeWire.validateRange(rangeHeader)
            val random = SecureRandom()
            val clientRandom = ByteArray(settings.randomSizeBytes).also { random.nextBytes(it) }
            // A random starting sequence, with ample room for incrementing within a 64-bit field.
            val sequence = random.nextInt(Int.MAX_VALUE).toLong()
            val dh = DiffieHellmanSession(settings.dhGroup).apply { createSession() }
            val proposal = HandshakeWire.proposal(config, settings)
            val psk = HandshakeKeySchedule.authenticationSecret(requireNotNull(config.config.symmetricKey).copyBytes(), config.config.macKey?.copyBytes())

            // TYPE 1: clear fields, but authenticate header + body (excluding the tag itself).
            val hello = ClientHelloPayload(sequence, proposal, requireNotNull(dh.exportPublicKeyBytes()),
                clientRandom, byteArrayOf())
            val firstFrame = sendClientHello(output, hello, psk)

            val (second, serverHello) = receiveServerHello(input, psk, hello, firstFrame)

            val helloHash = HandshakeCrypto.sha256(HandshakeWire.bytes(firstFrame), HandshakeWire.bytes(second))
            val dhSecret = dh.calculateSecret(serverHello.dhPublicKey)
            val sessionSecret = HandshakeKeySchedule.sessionSecret(psk, dhSecret, clientRandom, serverHello.srv, helloHash)
            dhSecret.fill(0) // Best effort: discard this byte-array copy after extraction.

            // TYPE 3: its own derived key/IV confirms possession of the DH-derived secret.
            val finished = ClientFinishedPayload(sequence + 2, HandshakeCrypto.sha256(serverHello.srv), media, rangeHeader)
            val thirdFrame = sendClientFinished(output, finished, sessionSecret, helloHash)

            val fullHash = HandshakeCrypto.sha256(HandshakeWire.bytes(firstFrame), HandshakeWire.bytes(second), HandshakeWire.bytes(thirdFrame))
            val keys = HandshakeKeySchedule.trafficKeys(sessionSecret, fullHash, keyBytes, cipher.ivBytes, cipher.macKeyBytes)
            sessionSecret.fill(0)
            psk.fill(0)
            // No fourth handshake message: proxy must await protected media to confirm server acceptance.
            return HandshakeSession(keys, media, sequence + 3, fullHash, rangeHeader, config.suite, config.macSuite)
        } catch (exception: Exception) {
            HandshakeWire.alert(output)
            throw exception
        }
    }

    private fun sendClientHello(output: OutputStream, hello: ClientHelloPayload, psk: ByteArray): ProtocolMessage {
        val body = HandshakePayloadCodec.encodeClientHelloBody(hello)
        val first = HandshakeWire.frame(MessageType.CLIENT_HELLO, body + ByteArray(32))
        val authKey = HandshakeKeySchedule.clientHelloAuthentication(psk, hello.clientRandom)
        val tag = HandshakeCrypto.hmac(authKey, ProtocolMessageCodec.encodeHeader(first.header), body)
        val firstFrame = first.copy(payload = body + tag)
        HandshakeWire.send(output, firstFrame, settings.maxPayloadBytes)
        return firstFrame
    }

    private fun receiveServerHello(input: InputStream, psk: ByteArray, hello: ClientHelloPayload,
                                    firstFrame: ProtocolMessage): Pair<ProtocolMessage, ServerHelloPayload> {
        val firstHash = HandshakeCrypto.sha256(HandshakeWire.bytes(firstFrame))
        // TYPE 2: public serverRandom prefix lets us derive bootstrap keys BEFORE decrypting SRV/B.
        val second = HandshakeWire.read(input, MessageType.SERVER_HELLO, settings.maxPayloadBytes)
        require(second.payload.size > settings.randomSizeBytes + settings.tagSizeBits / 8) { "ServerHello incompleto" }
        val serverRandom = second.payload.copyOfRange(0, settings.randomSizeBytes)
        val encrypted = second.payload.copyOfRange(settings.randomSizeBytes, second.payload.size)
        val bootstrap = HandshakeKeySchedule.serverHelloProtection(psk, hello.clientRandom, serverRandom, firstHash, keyBytes, cipher.ivBytes, cipher.macKeyBytes)
        val aad2 = ProtocolMessageCodec.encodeHeader(second.header) + serverRandom + firstHash
        val plaintext = cipher.decrypt(encrypted, bootstrap.key.copyBytes(), bootstrap.iv.copyBytes(), aad2, bootstrap.macKey?.copyBytes())
        val serverHello = HandshakePayloadCodec.decodeServerHello(plaintext, settings.randomSizeBytes)
        require(serverHello.seqy == hello.sequence + 1) { "Sequência do ServerHello inválida" }
        require(serverHello.acceptedConfig == hello.proposedConfig) { "CCC não corresponde à proposta autenticada" }
        return second to serverHello
    }

    private fun sendClientFinished(output: OutputStream, finished: ClientFinishedPayload,
                                    sessionSecret: ByteArray, helloHash: ByteArray): ProtocolMessage {
        val finishedBytes = HandshakePayloadCodec.encodeClientFinished(finished)
        val third = HandshakeWire.frame(MessageType.CLIENT_FINISHED, ByteArray(finishedBytes.size + settings.tagSizeBits / 8))
        val protection = HandshakeKeySchedule.clientFinishedProtection(sessionSecret, helloHash, keyBytes, cipher.ivBytes, cipher.macKeyBytes)
        val encryptedFinished = cipher.encrypt(finishedBytes, protection.key.copyBytes(), protection.iv.copyBytes(),
            ProtocolMessageCodec.encodeHeader(third.header) + helloHash, protection.macKey?.copyBytes())
        val thirdFrame = third.copy(payload = encryptedFinished)
        HandshakeWire.send(output, thirdFrame, settings.maxPayloadBytes)
        return thirdFrame
    }
}
