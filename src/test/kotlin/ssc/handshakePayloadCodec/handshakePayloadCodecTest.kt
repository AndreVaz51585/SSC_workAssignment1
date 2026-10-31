package ssc.handshakePayloadCodec

import ssc.config.CryptoConfigLoader
import ssc.config.CryptoConfigValidator
import ssc.config.HandshakeConfigValidator
import ssc.protocol.HandshakePayloadCodec
import ssc.protocol.dto.ClientFinishedPayload
import ssc.protocol.dto.ClientHelloPayload
import ssc.protocol.dto.ServerHelloPayload
import ssc.protocol.handshake.HandshakeWire
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class handshakePayloadCodecTest {
    private val config = CryptoConfigValidator.validate(CryptoConfigLoader.load("src/test/resources/config/proxycrypto.config"))
    private val proposal = HandshakeWire.proposal(config, HandshakeConfigValidator.validate(config))
    private val hello = ClientHelloPayload(123, proposal, byteArrayOf(1, 2, 3), ByteArray(32) { 4 }, ByteArray(32) { 5 })

    @Test
    fun `test client hello fields and public configuration round trip`() {
        val bytes = HandshakePayloadCodec.encodeClientHello(hello)
        val result = HandshakePayloadCodec.decodeClientHello(bytes, 32)
        assertEquals(hello.sequence, result.sequence)
        assertEquals(hello.proposedConfig, result.proposedConfig)
        assertContentEquals(hello.dhPublicKey, result.dhPublicKey)
        assertContentEquals(hello.clientRandom, result.clientRandom)
        assertContentEquals(hello.authenticationTag, result.authenticationTag)
    }

    @Test
    fun `test server hello and finished round trip including utf8 media names`() {
        val server = ServerHelloPayload(ByteArray(32) { 7 }, 124, proposal, byteArrayOf(8, 9))
        val result = HandshakePayloadCodec.decodeServerHello(HandshakePayloadCodec.encodeServerHello(server), 32)
        assertEquals(server.seqy, result.seqy)
        assertEquals(server.acceptedConfig, result.acceptedConfig)
        assertContentEquals(server.srv, result.srv)
        assertContentEquals(server.dhPublicKey, result.dhPublicKey)
        val finished = ClientFinishedPayload(125, ByteArray(32) { 10 }, "música de teste.mp4", "bytes=100-999")
        val decoded = HandshakePayloadCodec.decodeClientFinished(HandshakePayloadCodec.encodeClientFinished(finished))
        assertEquals(finished.sequence, decoded.sequence)
        assertEquals(finished.media, decoded.media)
        assertEquals(finished.rangeHeader, decoded.rangeHeader)
        assertContentEquals(finished.challengeResponse, decoded.challengeResponse)
    }

    @Test
    fun `test truncated and trailing fields are rejected`() {
        val bytes = HandshakePayloadCodec.encodeClientHello(hello)
        assertFailsWith<Exception> { HandshakePayloadCodec.decodeClientHello(bytes.copyOf(bytes.size - 1), 32) }
        assertFailsWith<Exception> { HandshakePayloadCodec.decodeClientHello(bytes + byteArrayOf(0), 32) }
        val oversized = bytes.copyOf().also { for (i in 8..11) it[i] = 127 }
        assertFailsWith<IllegalArgumentException> { HandshakePayloadCodec.decodeClientHello(oversized, 32) }
    }
}
