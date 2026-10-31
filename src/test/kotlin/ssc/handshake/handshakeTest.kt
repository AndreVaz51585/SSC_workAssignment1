package ssc.handshake

import ssc.config.CipherSuite
import ssc.config.CryptoConfigLoader
import ssc.config.CryptoConfigValidator
import ssc.config.HandshakeConfigValidator
import ssc.config.ValidatedCryptoConfig
import ssc.config.dto.KeyMaterial
import ssc.crypto.HandshakeCrypto
import ssc.crypto.HandshakeKeySchedule
import ssc.protocol.HandshakePayloadCodec
import ssc.protocol.ProtocolMessageCodec
import ssc.protocol.dto.MessageType
import ssc.protocol.handshake.HandshakeWire
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

import ssc.support.ProtocolTestSupport.exchangeHandshake as exchange

class handshakeTest {
    private fun config(): ValidatedCryptoConfig = CryptoConfigValidator.validate(
        CryptoConfigLoader.load("src/test/resources/config/proxycrypto.config"))

    @Test
    fun `test real sockets establish matching directional keys and session context`() {
        val result = exchange()
        val proxy = result.proxy.getOrThrow()
        val server = result.server.getOrThrow()
        assertEquals("música.mp4", server.media)
        assertEquals(proxy.firstMediaSequence, server.firstMediaSequence)
        assertContentEquals(proxy.sessionId(), server.sessionId())
        assertContentEquals(proxy.keys.proxyToServer.key.copyBytes(), server.keys.proxyToServer.key.copyBytes())
        assertContentEquals(proxy.keys.serverToProxy.key.copyBytes(), server.keys.serverToProxy.key.copyBytes())
        assertContentEquals(proxy.keys.proxyToServer.iv.copyBytes(), server.keys.proxyToServer.iv.copyBytes())
        assertFalse(proxy.keys.proxyToServer.key.copyBytes().contentEquals(proxy.keys.serverToProxy.key.copyBytes()))
    }

    @Test
    fun `test handshake also works with the other configured aes key sizes`() {
        for (bits in listOf(128, 192)) {
            val base = config().config
            val selected = CryptoConfigValidator.validate(base.copy(keySizeBits = bits,
                symmetricKey = KeyMaterial(ByteArray(bits / 8) { 11 })))
            val result = exchange(proxyConfig = selected, serverConfig = selected)
            val proxy = result.proxy.getOrThrow()
            val server = result.server.getOrThrow()
            assertEquals(bits, server.keys.serverToProxy.key.sizeBits)
            assertContentEquals(proxy.keys.serverToProxy.key.copyBytes(), server.keys.serverToProxy.key.copyBytes())
        }
    }

    @Test
    fun `test handshake settings reject unsupported or unsafe local values`() {
        val base = config().config
        val settings = requireNotNull(base.handshake)
        val invalid = listOf(
            settings.copy(dhGroup = "unknown"), settings.copy(kdf = "unknown"),
            settings.copy(authentication = "unknown"), settings.copy(tagSizeBits = 64),
            settings.copy(randomSizeBytes = 12), settings.copy(maxPayloadBytes = 1),
            settings.copy(maxPayloadBytes = Int.MAX_VALUE), settings.copy(socketTimeoutMillis = 0),
            settings.copy(maxStreamRecords = 0), settings.copy(maxStreamRecords = (1L shl 32) + 1),
        )
        for (value in invalid) {
            assertTrue(runCatching { HandshakeConfigValidator.validate(CryptoConfigValidator.validate(base.copy(handshake = value))) }.isFailure)
        }
        assertTrue(runCatching { HandshakeConfigValidator.validate(CryptoConfigValidator.validate(base.copy(handshake = null))) }.isFailure)
    }

    @Test
    fun `test fresh sessions derive different traffic keys`() {
        val first = exchange().server.getOrThrow()
        val second = exchange().server.getOrThrow()
        assertFalse(first.keys.serverToProxy.key.copyBytes().contentEquals(second.keys.serverToProxy.key.copyBytes()))
        assertFalse(first.sessionId().contentEquals(second.sessionId()))
    }

    @Test
    fun `test authenticated but incompatible proposal is rejected`() {
        val local = config()
        val result = exchange(proxyFrames = { bytes ->
            if (bytes[4].toInt() != 1) bytes else {
                val original = assertNotNull(ProtocolMessageCodec.read(bytes.inputStream(), 65536))
                val hello = HandshakePayloadCodec.decodeClientHello(original.payload, 32)
                val changed = hello.copy(proposedConfig = hello.proposedConfig.copy(ivSizeBits = 128))
                val body = HandshakePayloadCodec.encodeClientHelloBody(changed)
                val frame = HandshakeWire.frame(MessageType.CLIENT_HELLO, body + ByteArray(32))
                val key = HandshakeKeySchedule.clientHelloAuthentication(local.config.symmetricKey!!.copyBytes(), hello.clientRandom)
                val tag = HandshakeCrypto.hmac(key, ProtocolMessageCodec.encodeHeader(frame.header), body)
                HandshakeWire.bytes(frame.copy(payload = body + tag))
            }
        })
        assertTrue(result.proxy.isFailure)
        assertEquals("PCC não permitida pela configuração local", result.server.exceptionOrNull()?.message)
    }

    @Test
    fun `test ctr handshake rejects tag size inconsistent with selected hmac`() {
        val original = config().config
        val ctr = CryptoConfigValidator.validate(original.copy(mode = "CTR", ivSizeBits = 128,
            macAlgorithm = "HMAC-SHA256", macKey = KeyMaterial(ByteArray(32) { 22 }), macKeySizeBits = 256))
        val result = runCatching { HandshakeConfigValidator.validate(ctr) }
        assertTrue(result.isFailure)
    }
    @Test
    fun `test chacha handshake carries selected suite into both sessions`() {
        val selected = CryptoConfigValidator.validate(CryptoConfigLoader.load(
            "src/test/resources/config/profiles/chacha20-poly1305/proxy.config"))
        val result = exchange(proxyConfig = selected, serverConfig = selected)
        val proxy = result.proxy.getOrThrow()
        val server = result.server.getOrThrow()
        assertEquals(CipherSuite.CHACHA20_POLY1305, proxy.suite)
        assertEquals(proxy.suite, server.suite)
        assertContentEquals(proxy.keys.serverToProxy.key.copyBytes(), server.keys.serverToProxy.key.copyBytes())
    }

    @Test
    fun `test authenticated cipher suite mismatch is rejected without negotiation fallback`() {
        val original = config()
        val selected = CryptoConfigValidator.validate(original.config.copy(algorithm = "ChaCha20", mode = "Poly1305"))
        val result = exchange(proxyConfig = selected, serverConfig = original)
        assertTrue(result.proxy.isFailure)
        assertTrue(result.server.isFailure)
        assertEquals("PCC não permitida pela configuração local", result.server.exceptionOrNull()?.message)
    }

    @Test
    fun `test ctr peers derive matching independent mac keys`() {
        val selected = CryptoConfigValidator.validate(CryptoConfigLoader.load(
            "src/test/resources/config/profiles/aes256-ctr-hmac-sha256/proxy.config"))
        val result = exchange(proxyConfig = selected, serverConfig = selected)
        val proxy = result.proxy.getOrThrow()
        val server = result.server.getOrThrow()
        assertContentEquals(proxy.keys.serverToProxy.macKey!!.copyBytes(), server.keys.serverToProxy.macKey!!.copyBytes())
        assertFalse(proxy.keys.serverToProxy.key.copyBytes().contentEquals(proxy.keys.serverToProxy.macKey.copyBytes()))
    }


}
