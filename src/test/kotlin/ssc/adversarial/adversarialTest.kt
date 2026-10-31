package ssc.adversarial

import ssc.config.CryptoConfigLoader
import ssc.config.CryptoConfigValidator
import ssc.config.dto.KeyMaterial
import ssc.crypto.DiffieHellmanSession
import ssc.protocol.HandshakePayloadCodec
import ssc.protocol.ProtocolMessageCodec
import ssc.protocol.StreamPayloadCodec
import ssc.protocol.dto.ClientHelloPayload
import ssc.protocol.dto.MessageHeader
import ssc.protocol.dto.MessageType
import ssc.support.ProtocolTestSupport.exchangeHandshake
import ssc.support.ProtocolTestSupport.get
import ssc.support.ProtocolTestSupport.withHttpServers
import java.io.EOFException
import java.net.ProtocolException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** One named scenario per attack; all credentials below come from public TEST fixtures. */
class adversarialTest {
    private val profiles = listOf("aes256-gcm", "chacha20-poly1305",
        "aes256-ctr-hmac-sha256", "aes256-ctr-hmac-sha384", "aes256-ctr-hmac-sha512")

    private fun config(profile: String) = CryptoConfigValidator.validate(CryptoConfigLoader.load(
        "src/test/resources/config/profiles/$profile/proxy.config", "ProxyCryptoConfig"))

    // Header = version(2) || release(2) || type(1) || length(4).
    private fun type(bytes: ByteArray) = bytes[4].toInt() and 255
    private fun flip(bytes: ByteArray, offset: Int) = bytes.copyOf().also {
        it[offset] = (it[offset].toInt() xor 1).toByte()
    }

    /** Public Type 1 can be decoded by an observer. Preserve its old tag: attacker cannot recompute it. */
    private fun alterHello(bytes: ByteArray, change: (ClientHelloPayload) -> ClientHelloPayload): ByteArray {
        val frame = assertNotNull(ProtocolMessageCodec.read(bytes.inputStream(), 1024 * 1024))
        val hello = HandshakePayloadCodec.decodeClientHello(frame.payload, 32)
        val payload = HandshakePayloadCodec.encodeClientHello(change(hello))
        return ProtocolMessageCodec.encodeHeader(frame.header.copy(payloadLength = payload.size)) + payload
    }

    private fun expectIncompleteHttp(profile: String, change: (ByteArray) -> ByteArray) {
        withHttpServers(profile = profile, change = change) { port, _, original ->
            val response = get(port, "/video/sample.mp4")
            assertEquals(200, response.status, profile) // Valid metadata was delivered before the attack.
            assertEquals(original.size.toString(), response.headers["content-length"], profile)
            assertTrue(response.body.size < original.size, profile)
            assertContentEquals(original.copyOf(response.body.size), response.body, profile)
        }
    }

    @Test
    fun `test C0 authorized peers deliver exact media without any attack`() {
        for (profile in profiles) withHttpServers(profile = profile) { port, _, original ->
            val response = get(port, "/video/sample.mp4")
            assertEquals(200, response.status, profile)
            assertContentEquals(original, response.body, profile)
        }
    }

    @Test
    fun `test A1a attacker with guessed secrets cannot authenticate as proxy`() {
        for (profile in profiles) {
            // Given: the server keeps its legitimate secrets; attacker supplies guesses of valid sizes.
            val server = config(profile)
            val attacker = CryptoConfigValidator.validate(server.config.copy(
                symmetricKey = KeyMaterial(ByteArray(server.config.keySizeBits / 8) { 99 }),
                macKey = server.config.macKey?.let { KeyMaterial(ByteArray(it.sizeBits / 8) { 88 }) }))
            val replies = mutableListOf<Int>()
            // When: attacker starts the normal handshake using those guesses.
            val outcome = exchangeHandshake(proxyConfig = attacker, serverConfig = server,
                serverFrames = { bytes -> replies.add(type(bytes)); bytes })
            // Then: authentication, not local XML validation, rejects the attempt.
            assertTrue(outcome.proxy.isFailure, profile)
            assertEquals("Autenticação do ClientHello falhou", outcome.server.exceptionOrNull()?.message, profile)
            assertTrue(MessageType.ERROR_ALERT.code in replies, profile)
        }
    }

    @Test
    fun `test A1b knowing SKey alone is insufficient for ctr when MacKey is wrong`() {
        for (profile in profiles.filter { "ctr" in it }) {
            val server = config(profile)
            val attacker = CryptoConfigValidator.validate(server.config.copy(
                macKey = KeyMaterial(ByteArray(requireNotNull(server.config.macKey).sizeBits / 8) { 99 })))
            val outcome = exchangeHandshake(proxyConfig = attacker, serverConfig = server)
            assertTrue(outcome.proxy.isFailure, profile)
            assertEquals("Autenticação do ClientHello falhou", outcome.server.exceptionOrNull()?.message, profile)
        }
    }

    @Test
    fun `test A2a attacker cannot alter the public cryptographic proposal`() {
        for (profile in profiles) {
            val selected = config(profile)
            var changed = false
            val outcome = exchangeHandshake(selected, selected, proxyFrames = { bytes ->
                if (type(bytes) == 1) {
                    changed = true
                    alterHello(bytes) { it.copy(proposedConfig = it.proposedConfig.copy(keySizeBits = 128)) }
                } else bytes
            })
            assertTrue(changed, profile)
            assertEquals("Autenticação do ClientHello falhou", outcome.server.exceptionOrNull()?.message, profile)
        }
    }

    @Test
    fun `test A2b attacker cannot substitute its own valid dh public key`() {
        for (profile in profiles) {
            val selected = config(profile)
            val attackerDh = DiffieHellmanSession().apply { createSession() }
            val publicKey = assertNotNull(attackerDh.exportPublicKeyBytes())
            var changed = false
            val outcome = exchangeHandshake(selected, selected, proxyFrames = { bytes ->
                if (type(bytes) == 1) {
                    changed = true
                    alterHello(bytes) { it.copy(dhPublicKey = publicKey) }
                } else bytes
            })
            assertTrue(changed, profile)
            assertEquals("Autenticação do ClientHello falhou", outcome.server.exceptionOrNull()?.message, profile)
        }
    }

    @Test
    fun `test A2c attacker cannot alter server hello tag`() {
        for (profile in profiles) {
            val selected = config(profile)
            var changed = false
            val outcome = exchangeHandshake(selected, selected, serverFrames = { bytes ->
                if (type(bytes) == 2) { changed = true; flip(bytes, bytes.lastIndex) } else bytes
            })
            assertTrue(changed, profile)
            assertTrue(outcome.proxy.exceptionOrNull() is javax.crypto.AEADBadTagException, profile)
            assertTrue(outcome.server.isFailure, profile)
        }
    }

    @Test
    fun `test A2d attacker cannot alter client finished tag`() {
        for (profile in profiles) {
            val selected = config(profile)
            var changed = false
            val outcome = exchangeHandshake(selected, selected, proxyFrames = { bytes ->
                if (type(bytes) == 3) { changed = true; flip(bytes, bytes.lastIndex) } else bytes
            })
            assertTrue(changed, profile)
            assertTrue(outcome.server.exceptionOrNull() is javax.crypto.AEADBadTagException, profile)
            // Proxy may have sent Type 3; only the server's acceptance establishes this side of the session.
        }
    }

    @Test
    fun `test A2e unexpected handshake type is rejected in the initial state`() {
        val outcome = exchangeHandshake(proxyFrames = { bytes ->
            if (type(bytes) == 1) bytes.copyOf().also { it[4] = 3 } else bytes
        })
        assertEquals("Mensagem inesperada no estado atual do handshake", outcome.server.exceptionOrNull()?.message)
        assertTrue(outcome.proxy.isFailure)
    }

    @Test
    fun `test A2f attacker cannot replace the public server random`() {
        for (profile in profiles) {
            val selected = config(profile)
            var changed = false
            val outcome = exchangeHandshake(selected, selected, serverFrames = { bytes ->
                if (type(bytes) == 2) {
                    changed = true
                    flip(bytes, ProtocolMessageCodec.HEADER_SIZE)
                } else bytes
            })
            assertTrue(changed, profile)
            assertTrue(outcome.proxy.exceptionOrNull() is javax.crypto.AEADBadTagException, profile)
            assertTrue(outcome.server.isFailure, profile)
        }
    }

    @Test
    fun `test A3a modified media ciphertext is never delivered as valid content`() {
        for (profile in profiles) {
            var blocks = 0
            var changed = false
            expectIncompleteHttp(profile) { bytes ->
                if (type(bytes) == 4 && ++blocks == 2) {
                    changed = true
                    flip(bytes, ProtocolMessageCodec.HEADER_SIZE + StreamPayloadCodec.SEQUENCE_BYTES)
                } else bytes
            }
            assertTrue(changed, profile)
        }
    }

    @Test
    fun `test A3b forged media authentication tag is rejected`() {
        for (profile in profiles) {
            var blocks = 0
            var changed = false
            expectIncompleteHttp(profile) { bytes ->
                if (type(bytes) == 4 && ++blocks == 2) {
                    changed = true
                    flip(bytes, bytes.lastIndex)
                } else bytes
            }
            assertTrue(changed, profile)
        }
    }

    @Test
    fun `test A3c altered metadata is rejected before browser response headers`() {
        for (profile in profiles) {
            var changed = false
            withHttpServers(profile = profile, change = { bytes ->
                if (!changed && type(bytes) == 4) { changed = true; flip(bytes, bytes.lastIndex) } else bytes
            }) { port, _, _ ->
                val response = get(port, "/video/sample.mp4")
                assertEquals(502, response.status, profile)
                assertTrue(response.body.isEmpty(), profile)
            }
            assertTrue(changed, profile)
        }
    }

    @Test
    fun `test A4a replayed media record aborts instead of duplicating browser data`() {
        for (profile in profiles) {
            var blocks = 0
            var repeated = false
            expectIncompleteHttp(profile) { bytes ->
                if (type(bytes) == 4 && ++blocks == 2) { repeated = true; bytes + bytes } else bytes
            }
            assertTrue(repeated, profile)
        }
    }

    @Test
    fun `test A4b old server hello cannot authenticate a new session`() {
        for (profile in profiles) {
            val selected = config(profile)
            var recorded: ByteArray? = null
            exchangeHandshake(selected, selected, serverFrames = { bytes ->
                if (type(bytes) == 2) recorded = bytes.copyOf()
                bytes
            }).server.getOrThrow()
            val oldHello = assertNotNull(recorded)
            val outcome = exchangeHandshake(selected, selected,
                serverFrames = { bytes -> if (type(bytes) == 2) oldHello else bytes })
            assertTrue(outcome.proxy.exceptionOrNull() is javax.crypto.AEADBadTagException, profile)
            assertTrue(outcome.server.isFailure, profile)
        }
    }

    @Test
    fun `test A4c old client finished cannot complete a new server session`() {
        for (profile in profiles) {
            val selected = config(profile)
            var recorded: ByteArray? = null
            exchangeHandshake(selected, selected, proxyFrames = { bytes ->
                if (type(bytes) == 3) recorded = bytes.copyOf()
                bytes
            }).server.getOrThrow()
            val oldFinished = assertNotNull(recorded)
            val outcome = exchangeHandshake(selected, selected,
                proxyFrames = { bytes -> if (type(bytes) == 3) oldFinished else bytes })
            assertTrue(outcome.server.exceptionOrNull() is javax.crypto.AEADBadTagException, profile)
        }
    }

    @Test
    fun `test A5a removing a media record leaves an incomplete response`() {
        for (profile in profiles) {
            var blocks = 0
            var removed = false
            expectIncompleteHttp(profile) { bytes ->
                if (type(bytes) == 4 && ++blocks == 2) { removed = true; byteArrayOf() } else bytes
            }
            assertTrue(removed, profile)
        }
    }

    @Test
    fun `test A5b swapping two media records is rejected`() {
        for (profile in profiles) {
            var blocks = 0
            var held: ByteArray? = null
            var reordered = false
            expectIncompleteHttp(profile) { bytes ->
                if (type(bytes) == 4) blocks++
                when {
                    type(bytes) == 4 && blocks == 2 -> { held = bytes; byteArrayOf() }
                    type(bytes) == 4 && blocks == 3 -> { reordered = true; bytes + assertNotNull(held) }
                    else -> bytes
                }
            }
            assertTrue(reordered, profile)
        }
    }

    @Test
    fun `test A6a missing end never completes the http body`() {
        for (profile in profiles) {
            var removed = false
            expectIncompleteHttp(profile) { bytes ->
                if (type(bytes) == 5) { removed = true; byteArrayOf() } else bytes
            }
            assertTrue(removed, profile)
        }
    }

    @Test
    fun `test A6b altered end never confirms successful termination`() {
        for (profile in profiles) {
            var changed = false
            expectIncompleteHttp(profile) { bytes ->
                if (type(bytes) == 5) { changed = true; flip(bytes, bytes.lastIndex) } else bytes
            }
            assertTrue(changed, profile)
        }
    }

    @Test
    fun `test A7a oversized length is rejected before allocating or reading the body`() {
        val maximum = 2048
        val header = ProtocolMessageCodec.encodeHeader(MessageHeader(message = MessageType.CLIENT_HELLO,
            payloadLength = maximum + 1))
        // No body is supplied. Reading it would produce EOFException, not this ProtocolException.
        assertFailsWith<ProtocolException> { ProtocolMessageCodec.read(header.inputStream(), maximum) }
    }

    @Test
    fun `test A7b truncated header is never interpreted as a complete message`() {
        val header = ProtocolMessageCodec.encodeHeader(MessageHeader(message = MessageType.CLIENT_HELLO, payloadLength = 0))
        assertFailsWith<EOFException> {
            ProtocolMessageCodec.read(header.copyOf(ProtocolMessageCodec.HEADER_SIZE - 1).inputStream(), 2048)
        }
    }

    @Test
    fun `test A7c unknown type is rejected by framing parser`() {
        val header = ProtocolMessageCodec.encodeHeader(MessageHeader(message = MessageType.CLIENT_HELLO, payloadLength = 0))
            .also { it[4] = 99 }
        assertFailsWith<ProtocolException> { ProtocolMessageCodec.read(header.inputStream(), 2048) }
    }
}
