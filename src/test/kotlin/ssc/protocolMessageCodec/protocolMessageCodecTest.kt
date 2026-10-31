package ssc.protocolMessageCodec

import ssc.protocol.ProtocolMessageCodec
import ssc.protocol.dto.MessageHeader
import ssc.protocol.dto.MessageType
import ssc.protocol.dto.ProtocolMessage
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.FilterInputStream
import java.net.ProtocolException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class protocolMessageCodecTest {
    private fun message(
        type: MessageType = MessageType.CLIENT_HELLO,
        payload: ByteArray = byteArrayOf(0, 127, 128.toByte(), 255.toByte()),
        version: Int = 1,
        release: Int = 1,
    ) = ProtocolMessage(MessageHeader(version, release, type, payload.size), payload)

    private fun encode(message: ProtocolMessage): ByteArray = ByteArrayOutputStream().also {
        ProtocolMessageCodec.write(it, message)
    }.toByteArray()

    @Test
    fun `test write produces the exact nine byte binary header followed by raw payload`() {
        val encoded = encode(message(version = 0x1234, release = 0x5678))
        assertContentEquals(
            byteArrayOf(0x12, 0x34, 0x56, 0x78, 1, 0, 0, 0, 4, 0, 127, 128.toByte(), 255.toByte()),
            encoded,
        )
    }

    @Test
    fun `test every message type can be written and read including code 255`() {
        for (type in MessageType.entries) {
            val expected = message(type)
            val actual = assertNotNull(ProtocolMessageCodec.read(encode(expected).inputStream(), 4))
            assertEquals(expected.header, actual.header)
            assertContentEquals(expected.payload, actual.payload)
        }
    }

    @Test
    fun `test unsigned two byte header fields are preserved`() {
        val expected = message(version = 65535, release = 32768)
        val actual = assertNotNull(ProtocolMessageCodec.read(encode(expected).inputStream(), 4))
        assertEquals(expected.header, actual.header)
    }

    @Test
    fun `test empty payload is a complete message rather than eof`() {
        val expected = message(payload = byteArrayOf())
        val actual = assertNotNull(ProtocolMessageCodec.read(encode(expected).inputStream(), 0))
        assertEquals(expected.header, actual.header)
        assertContentEquals(byteArrayOf(), actual.payload)
    }

    @Test
    fun `test clean eof returns null`() {
        assertNull(ProtocolMessageCodec.read(byteArrayOf().inputStream(), 16))
    }

    @Test
    fun `test every truncated header is rejected`() {
        val complete = encode(message())
        for (size in 1 until ProtocolMessageCodec.HEADER_SIZE) {
            assertFailsWith<EOFException> {
                ProtocolMessageCodec.read(complete.copyOf(size).inputStream(), 4)
            }
        }
    }

    @Test
    fun `test every truncated payload is rejected`() {
        val complete = encode(message())
        for (size in ProtocolMessageCodec.HEADER_SIZE until complete.size) {
            assertFailsWith<EOFException> {
                ProtocolMessageCodec.read(complete.copyOf(size).inputStream(), 4)
            }
        }
    }

    @Test
    fun `test input arriving one byte at a time is accumulated correctly`() {
        val expected = message()
        val input = object : FilterInputStream(ByteArrayInputStream(encode(expected))) {
            override fun read(bytes: ByteArray, offset: Int, length: Int): Int =
                super.read(bytes, offset, minOf(length, 1))
        }
        val actual = assertNotNull(ProtocolMessageCodec.read(input, 4))
        assertEquals(expected.header, actual.header)
        assertContentEquals(expected.payload, actual.payload)
    }

    @Test
    fun `test consecutive messages are read without consuming the next frame`() {
        val first = message()
        val second = message(MessageType.ERROR_ALERT, byteArrayOf(5, 6))
        val input = (encode(first) + encode(second)).inputStream()
        for (expected in listOf(first, second)) {
            val actual = assertNotNull(ProtocolMessageCodec.read(input, 4))
            assertEquals(expected.header, actual.header)
            assertContentEquals(expected.payload, actual.payload)
        }
        assertNull(ProtocolMessageCodec.read(input, 4))
    }

    @Test
    fun `test unknown type code is rejected`() {
        val invalid = encode(message()).also { it[4] = 6 }
        assertFailsWith<ProtocolException> { ProtocolMessageCodec.read(invalid.inputStream(), 4) }
    }

    @Test
    fun `test negative declared payload length is rejected`() {
        val invalid = encode(message()).also { bytes ->
            for (i in 5..8) bytes[i] = 255.toByte()
        }
        assertFailsWith<ProtocolException> { ProtocolMessageCodec.read(invalid.inputStream(), 4) }
    }

    @Test
    fun `test oversized payload is rejected before reading its body`() {
        val header = encode(message()).copyOf(ProtocolMessageCodec.HEADER_SIZE)
        // Declares 4 bytes but provides none. A length error must occur before an EOF error.
        assertFailsWith<ProtocolException> { ProtocolMessageCodec.read(header.inputStream(), 3) }
    }

    @Test
    fun `test invalid caller limit is rejected`() {
        assertFailsWith<IllegalArgumentException> {
            ProtocolMessageCodec.read(byteArrayOf().inputStream(), -1)
        }
    }

    @Test
    fun `test write rejects out of range header values without writing partial output`() {
        for (invalid in listOf(-1, 65536, 256 + 65536)) {
            for (candidate in listOf(message(version = invalid), message(release = invalid))) {
                val output = ByteArrayOutputStream()
                assertFailsWith<IllegalArgumentException> { ProtocolMessageCodec.write(output, candidate) }
                assertEquals(0, output.size())
            }
        }
    }

    @Test
    fun `test write rejects mismatched payload length`() {
        val valid = message()
        val invalid = valid.copy(header = valid.header.copy(payloadLength = 100))
        val output = ByteArrayOutputStream()
        assertFailsWith<IllegalArgumentException> { ProtocolMessageCodec.write(output, invalid) }
        assertEquals(0, output.size())
    }

    @Test
    fun `test write flushes without closing the caller stream`() {
        var flushed = false
        var closed = false
        val output = object : ByteArrayOutputStream() {
            override fun flush() { flushed = true }
            override fun close() { closed = true }
        }
        ProtocolMessageCodec.write(output, message())
        assertTrue(flushed)
        assertEquals(false, closed)
    }
}
