package ssc.secureStream

import ssc.config.CipherSuite
import ssc.config.CryptoConfigLoader
import ssc.config.CryptoConfigValidator
import ssc.config.HandshakeConfigValidator
import ssc.config.dto.KeyMaterial
import ssc.crypto.ProtectionKeys
import ssc.crypto.SessionKeys
import ssc.metrics.StreamMetrics
import ssc.protocol.ProtocolMessageCodec
import ssc.protocol.StreamPayloadCodec
import ssc.protocol.dto.EndStreamPayload
import ssc.protocol.dto.MediaResponseMetadata
import ssc.protocol.dto.MessageHeader
import ssc.protocol.dto.MessageType
import ssc.protocol.dto.ProtocolMessage
import ssc.protocol.handshake.HandshakeSession
import ssc.protocol.handshake.ProxyHandshake
import ssc.protocol.handshake.ServerHandshake
import ssc.protocol.stream.SecureStreamReceiver
import ssc.protocol.stream.SecureStreamSender
import ssc.protocol.stream.StreamRecordProtection
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.AEADBadTagException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class secureStreamTest {
    private fun config() = CryptoConfigValidator.validate(
        CryptoConfigLoader.load("src/test/resources/config/proxycrypto.config"))
    private val settings get() = HandshakeConfigValidator.validate(config())

    // Public, deterministic TEST material. Real sessions obtain these values from authenticated DH.
    private fun session(keyByte: Int = 22, idByte: Int = 33, first: Long = 100): HandshakeSession {
        val forward = ProtectionKeys(KeyMaterial(ByteArray(32) { 11 }), KeyMaterial(ByteArray(12) { 12 }))
        val reverse = ProtectionKeys(KeyMaterial(ByteArray(32) { keyByte.toByte() }), KeyMaterial(ByteArray(12) { 23 }))
        return HandshakeSession(SessionKeys(forward, reverse), "sample.mp4", first, ByteArray(32) { idByte.toByte() }, suite = CipherSuite.AES_GCM)
    }

    private fun wire(data: ByteArray, blockSize: Int = 1024): ByteArray = ByteArrayOutputStream().also {
        SecureStreamSender(session(), settings).send(data.inputStream(), it, MediaResponseMetadata.full(data.size.toLong()), blockSize)
    }.toByteArray()

    private fun frames(wire: ByteArray): List<ProtocolMessage> = buildList {
        val input = wire.inputStream()
        while (true) add(ProtocolMessageCodec.read(input, settings.maxPayloadBytes) ?: break)
    }

    private fun serialize(frames: List<ProtocolMessage>) = ByteArrayOutputStream().also { output ->
        frames.forEach { ProtocolMessageCodec.write(output, it) }
    }.toByteArray()

    private fun receive(wire: ByteArray, target: ByteArrayOutputStream = ByteArrayOutputStream(),
                        selected: HandshakeSession = session()): ByteArray {
        val count = SecureStreamReceiver(selected, settings).receive(wire.inputStream(), target)
        assertEquals(target.size().toLong(), count)
        return target.toByteArray()
    }

    @Test
    fun `test metrics distinguish encrypted payload protocol overhead and forwarded media`() {
        for (size in listOf(0, 1, 2050)) {
            val encoded = wire(ByteArray(size))
            val records = frames(encoded)
            val metrics = StreamMetrics()
            SecureStreamReceiver(session(), settings, metrics).receive(encoded.inputStream(), ByteArrayOutputStream())
            val result = requireNotNull(metrics.result)
            val blocks = (size + 1023L) / 1024
            assertTrue(result.completed)
            assertEquals(size.toLong(), result.metadata?.totalLength)
            assertEquals(blocks, result.encryptedMediaBlocksReceived)
            assertEquals(blocks, result.forwardedMediaBlocks)
            assertEquals(size.toLong(), result.decryptedMediaBytes)
            assertEquals(size.toLong(), result.forwardedMediaBytes)
            assertEquals(encoded.size.toLong(), result.recordBytesReceived)
            assertEquals(records.size.toLong(), result.completeFramesReceived)
            assertEquals(blocks + 1, result.type4FramesReceived) // Metadata is also Type 4.
            assertEquals(size + blocks * (8 + 1 + settings.tagSizeBits / 8), result.encryptedMediaPayloadBytes)
        }
    }

    @Test
    fun `test metrics retain original file length for a partial response`() {
        val meta = MediaResponseMetadata(206, MediaResponseMetadata.VIDEO_TYPE, 1000, 3, 10, 12)
        val encoded = authenticated(MessageType.MEDIA_BLOCK to StreamPayloadCodec.encodeMetadata(meta),
            MessageType.MEDIA_BLOCK to StreamPayloadCodec.encodeData(byteArrayOf(1, 2, 3)),
            MessageType.END_STREAM to StreamPayloadCodec.encodeEnd(EndStreamPayload(102, "a".repeat(64)), 64))
        val metrics = StreamMetrics()
        SecureStreamReceiver(session(), settings, metrics).receive(encoded.inputStream(), ByteArrayOutputStream())
        val result = requireNotNull(metrics.result)
        assertEquals(1000L, result.metadata?.totalLength)
        assertEquals(3L, result.metadata?.contentLength)
        assertEquals(3L, result.forwardedMediaBytes)
        assertTrue(result.completed)
    }

    @Test
    fun `test metrics count rejected complete frame without counting unauthenticated media`() {
        val records = frames(wire(ByteArray(2050))).toMutableList()
        records[2].payload[records[2].payload.lastIndex] = (records[2].payload.last().toInt() xor 1).toByte()
        val metrics = StreamMetrics()
        assertFailsWith<AEADBadTagException> {
            SecureStreamReceiver(session(), settings, metrics).receive(serialize(records).inputStream(), ByteArrayOutputStream())
        }
        val result = requireNotNull(metrics.result)
        assertFalse(result.completed)
        assertEquals(3L, result.completeFramesReceived) // Metadata, authentic DATA, altered DATA.
        assertEquals(1L, result.encryptedMediaBlocksReceived)
        assertEquals(1024L, result.decryptedMediaBytes)
        assertEquals(0L, result.forwardedMediaBytes) // Last authentic block remains pending.
    }

    @Test
    fun `test metrics missing end reports received data and only successfully forwarded prefix`() {
        val encoded = serialize(frames(wire(ByteArray(2050))).dropLast(1))
        val metrics = StreamMetrics()
        val output = ByteArrayOutputStream()
        assertFailsWith<EOFException> {
            SecureStreamReceiver(session(), settings, metrics).receive(encoded.inputStream(), output)
        }
        val result = requireNotNull(metrics.result)
        assertFalse(result.completed)
        assertEquals(2050L, result.decryptedMediaBytes)
        assertEquals(2048L, result.forwardedMediaBytes)
        assertEquals(output.size().toLong(), result.forwardedMediaBytes)
        assertEquals(3L, result.encryptedMediaBlocksReceived)
        assertEquals(2L, result.forwardedMediaBlocks)
    }

    @Test
    fun `test metrics failed browser write is not reported as forwarded`() {
        val metrics = StreamMetrics()
        val broken = object : OutputStream() {
            override fun write(b: Int) { throw java.io.IOException("Browser disconnected") }
        }
        assertFailsWith<java.io.IOException> {
            SecureStreamReceiver(session(), settings, metrics).receive(wire(ByteArray(2)).inputStream(), broken)
        }
        val result = requireNotNull(metrics.result)
        assertFalse(result.completed)
        assertEquals(2L, result.decryptedMediaBytes)
        assertEquals(0L, result.forwardedMediaBytes)
        assertEquals(0L, result.forwardedMediaBlocks)
    }

    @Test
    fun `test metrics use monotonic interval decimal kilobytes and single line safe log values`() {
        var now = 100L
        val metrics = StreamMetrics { now }
        val output = ByteArrayOutputStream()
        SecureStreamReceiver(session(), settings, metrics).receive(wire(ByteArray(2000)).inputStream(), output) {
            now += 2_000_000_000L
        }
        val result = requireNotNull(metrics.result)
        assertEquals(2_000_000_000L, result.elapsedNanos)
        assertEquals(1.0, result.throughputKBps)
        now += 100_000_000_000L
        assertEquals(2_000_000_000L, result.elapsedNanos) // Snapshot does not include logging time.
        val line = result.toLogLine("request-1", "música = teste\n.mp4", "AES_GCM", 256, null)
        assertFalse(line.contains('\n'))
        assertTrue(line.contains("resource=m%C3%BAsica+%3D+teste%0A.mp4"))
        assertTrue(line.contains("throughputKBps=1.000"))
        assertTrue(line.contains("transfer=complete"))
        val summary = result.toSummary("música\n.mp4")
        assertEquals(2, summary.lines().size)
        assertTrue(summary.contains("[STREAM OK]"))
        assertTrue(summary.contains("música\\n.mp4"))
        assertTrue(summary.contains("blocos autenticados/encaminhados: 2/2"))
        assertTrue(summary.contains("enviados 2.00 kB/2.00 kB"))
        assertFalse(summary.contains("requestId"))
        assertFalse(summary.contains("event="))
        assertFalse(result.toSummary("bad\u001b[31m.mp4").contains('\u001b'))
        val aborted = result.copy(completed = false).toSummary("sample.mp4", "Broken pipe\nextra")
        assertEquals(2, aborted.lines().size)
        assertTrue(aborted.contains("[STREAM INTERROMPIDO]"))
        assertTrue(aborted.contains("motivo: Broken pipe\\nextra"))
    }

    @Test
    fun `test browser disconnect can leave two authenticated blocks without completed forwarding`() {
        val metrics = StreamMetrics()
        var writes = 0
        val browser = object : ByteArrayOutputStream() {
            override fun write(bytes: ByteArray, offset: Int, length: Int) {
                if (++writes == 3) throw java.io.IOException("Browser disconnected")
                super.write(bytes, offset, length)
            }
        }
        assertFailsWith<java.io.IOException> {
            SecureStreamReceiver(session(), settings, metrics).receive(wire(ByteArray(4096)).inputStream(), browser)
        }
        val result = requireNotNull(metrics.result)
        assertFalse(result.completed)
        assertEquals(4L, result.encryptedMediaBlocksReceived)
        assertEquals(2L, result.forwardedMediaBlocks)
        assertEquals(4096L, result.decryptedMediaBytes)
        assertEquals(2048L, result.forwardedMediaBytes)
        assertEquals(2048, browser.size())
        // No duplicated output: two writes succeeded, the third failed, the fourth was not attempted.
        assertEquals(3, writes)
    }

    @Test
    fun `test media round trip includes empty file and partial final block`() {
        for (size in listOf(0, 1, 1024, 1025, 70001)) {
            val data = ByteArray(size) { (it * 17).toByte() }
            val encoded = wire(data)
            assertContentEquals(data, receive(encoded))
            val records = frames(encoded)
            assertEquals(MessageType.END_STREAM, records.last().header.message)
            assertEquals((size + 1023) / 1024 + 2, records.size)
            records.forEachIndexed { index, frame ->
                assertEquals(100L + index, StreamPayloadCodec.decodeSequence(frame.payload))
            }
        }
    }

    @Test
    fun `test ciphertext hides media and repeated blocks use different nonces`() {
        val block = ByteArray(1024) { 77 }
        val records = frames(wire(block + block))
        val first = records[1].payload.copyOfRange(8, records[1].payload.size)
        val second = records[2].payload.copyOfRange(8, records[2].payload.size)
        assertFalse(first.contentEquals(second))
        assertFalse(first.copyOfRange(0, 1024).contentEquals(block))
        assertEquals(8 + 1 + 1024 + 16, records[1].payload.size)
        val protection = StreamRecordProtection(session(), settings)
        assertFalse(protection.nonce(100).contentEquals(protection.nonce(101)))
        assertEquals(12, protection.nonce(100).size)
        protection.destroy()
    }

    @Test
    fun `test fragmented tcp reads still reconstruct records`() {
        val data = ByteArray(5000) { it.toByte() }
        val input = object : ByteArrayInputStream(wire(data)) {
            override fun read(b: ByteArray, off: Int, len: Int): Int = super.read(b, off, minOf(3, len))
        }
        val output = ByteArrayOutputStream()
        assertEquals(data.size.toLong(), SecureStreamReceiver(session(), settings).receive(input, output))
        assertContentEquals(data, output.toByteArray())
    }

    @Test
    fun `test modified ciphertext or tag releases no bytes from the bad block`() {
        for (offset in listOf(8, -1)) {
            val records = frames(wire(ByteArray(100) { 7 })).toMutableList()
            val first = records.first()
            records[0] = first.copy(payload = first.payload.copyOf().also {
                val index = if (offset < 0) it.lastIndex else offset
                it[index] = (it[index].toInt() xor 1).toByte()
            })
            val output = ByteArrayOutputStream()
            assertFailsWith<AEADBadTagException> { receive(serialize(records), output) }
            assertEquals(0, output.size())
        }
    }

    @Test
    fun `test header type sequence and session context cannot be substituted`() {
        val records = frames(wire(ByteArray(10) { 2 }))
        val first = records.first()
        val changedType = first.copy(header = first.header.copy(message = MessageType.END_STREAM))
        assertFailsWith<AEADBadTagException> { receive(serialize(listOf(changedType))) }
        val changedSequence = first.copy(payload = first.payload.copyOf().also { it[7] = 101 })
        assertFailsWith<IllegalArgumentException> { receive(serialize(listOf(changedSequence))) }
        assertFailsWith<AEADBadTagException> { receive(serialize(records), selected = session(idByte = 99)) }
        assertFailsWith<AEADBadTagException> { receive(serialize(records), selected = session(keyByte = 99)) }
        val changedVersion = first.copy(header = first.header.copy(version = 2))
        assertFailsWith<IllegalArgumentException> { receive(serialize(listOf(changedVersion))) }
    }

    @Test
    fun `test replay reordering and omitted block abort reception`() {
        val records = frames(wire(ByteArray(2500) { 3 }))
        val invalid = listOf(
            listOf(records[0], records[0]) + records.drop(1),
            listOf(records[1], records[0]) + records.drop(2),
            listOf(records[0]) + records.drop(2),
            records.drop(1),
        )
        for (changed in invalid) assertFailsWith<IllegalArgumentException> { receive(serialize(changed)) }
    }

    @Test
    fun `test eof without authenticated end is never successful`() {
        val records = frames(wire(ByteArray(2000) { 3 }))
        assertFailsWith<EOFException> { receive(serialize(records.dropLast(1))) }
        assertFailsWith<EOFException> { receive(byteArrayOf()) }
        val encoded = serialize(records)
        assertFailsWith<EOFException> { receive(encoded.copyOf(encoded.size - 1)) }
    }

    @Test
    fun `test tampered end tag is rejected even after all media arrived`() {
        val records = frames(wire(ByteArray(50) { 9 })).toMutableList()
        val end = records.last()
        records[records.lastIndex] = end.copy(payload = end.payload.copyOf().also {
            it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
        })
        val output = ByteArrayOutputStream()
        assertFailsWith<AEADBadTagException> { receive(serialize(records), output) }
        assertEquals(0, output.size()) // Final block is withheld until authenticated END.
    }

    @Test
    fun `test authenticated end validates marker inner sequence and random string`() {
        val valid = StreamPayloadCodec.encodeEnd(EndStreamPayload(101, "a".repeat(64)), 64)
        val invalid = listOf(
            valid.copyOf().also { it[7] = 102 },
            valid.copyOf().also { it[8] = 'X'.code.toByte() },
            valid.copyOf().also { it[it.lastIndex] = 'Z'.code.toByte() },
            valid.copyOf(valid.size - 1),
        )
        for (plaintext in invalid) {
            val protection = StreamRecordProtection(session(), settings)
            val meta = protection.protect(MessageType.MEDIA_BLOCK, 100,
                StreamPayloadCodec.encodeMetadata(MediaResponseMetadata.full(0)))
            val frame = protection.protect(MessageType.END_STREAM, 101, plaintext)
            assertFailsWith<IllegalArgumentException> { receive(serialize(listOf(meta, frame))) }
            protection.destroy()
        }
    }

    @Test
    fun `test unexpected message and oversized payload fail closed`() {
        val alert = ProtocolMessage(MessageHeader(message = MessageType.ERROR_ALERT, payloadLength = 1), byteArrayOf(1))
        assertFailsWith<IllegalArgumentException> { receive(serialize(listOf(alert))) }
        val header = MessageHeader(message = MessageType.MEDIA_BLOCK, payloadLength = settings.maxPayloadBytes + 1)
        assertFailsWith<java.net.ProtocolException> { receive(ProtocolMessageCodec.encodeHeader(header)) }
        assertFailsWith<IllegalArgumentException> {
            SecureStreamSender(session(), settings).send(byteArrayOf(1).inputStream(), ByteArrayOutputStream(), MediaResponseMetadata.full(1), settings.maxPayloadBytes)
        }
    }

    @Test
    fun `test empty authenticated media block is rejected`() {
        val protection = StreamRecordProtection(session(), settings)
        val frame = protection.protect(MessageType.MEDIA_BLOCK, 100, byteArrayOf())
        assertFailsWith<IllegalArgumentException> { receive(serialize(listOf(frame))) }
        protection.destroy()
    }

    @Test
    fun `test sender receiver and session cannot restart record counters`() {
        val s = session()
        val sender = SecureStreamSender(s, settings)
        sender.send(byteArrayOf(1).inputStream(), ByteArrayOutputStream(), MediaResponseMetadata.full(1))
        assertFailsWith<IllegalStateException> { sender.send(byteArrayOf(2).inputStream(), ByteArrayOutputStream(), MediaResponseMetadata.full(1)) }
        assertFailsWith<IllegalStateException> { SecureStreamSender(s, settings) }
        val r = session()
        val receiver = SecureStreamReceiver(r, settings)
        receiver.receive(wire(byteArrayOf(1)).inputStream(), ByteArrayOutputStream())
        assertFailsWith<IllegalStateException> { receiver.receive(wire(byteArrayOf(1)).inputStream(), ByteArrayOutputStream()) }
        assertFailsWith<IllegalStateException> { SecureStreamReceiver(r, settings) }
    }

    @Test
    fun `test failed send also consumes the sender`() {
        val sender = SecureStreamSender(session(), settings)
        val broken = object : OutputStream() { override fun write(b: Int) { throw java.io.IOException("broken") } }
        assertFailsWith<java.io.IOException> { sender.send(byteArrayOf(1).inputStream(), broken, MediaResponseMetadata.full(1)) }
        assertFailsWith<IllegalStateException> { sender.send(byteArrayOf(1).inputStream(), ByteArrayOutputStream(), MediaResponseMetadata.full(1)) }
    }

    @Test
    fun `test record count and sequence overflow require a fresh session`() {
        val protection = StreamRecordProtection(session(), settings)
        assertFailsWith<IllegalArgumentException> {
            protection.protect(MessageType.MEDIA_BLOCK, 100 + StreamRecordProtection.MAX_RECORDS, byteArrayOf(1))
        }
        protection.destroy()
        assertFailsWith<IllegalArgumentException> {
            SecureStreamSender(session(first = Long.MAX_VALUE - 1), settings)
                .send(byteArrayOf(1).inputStream(), ByteArrayOutputStream(), MediaResponseMetadata.full(1))
        }
    }

    @Test
    fun `test configured record limit includes authenticated end`() {
        val profile = settings.copy(maxStreamRecords = 3)
        val output = ByteArrayOutputStream()
        SecureStreamSender(session(), profile).send(byteArrayOf(1).inputStream(), output, MediaResponseMetadata.full(1))
        val received = ByteArrayOutputStream()
        assertEquals(1L, SecureStreamReceiver(session(), profile).receive(output.toByteArray().inputStream(), received))
        assertFailsWith<IllegalArgumentException> {
            SecureStreamSender(session(), profile).send(byteArrayOf(1, 2).inputStream(), ByteArrayOutputStream(), MediaResponseMetadata.full(2), 1)
        }
        assertFailsWith<IllegalArgumentException> {
            SecureStreamReceiver(session(), profile.copy(maxStreamRecords = 2))
                .receive(output.toByteArray().inputStream(), ByteArrayOutputStream())
        }
    }

    @Test
    fun `test real handshake and protected stream share the same tcp connection for all aes sizes`() {
        for (bits in listOf(128, 192, 256)) {
            val base = config().config
            val selected = CryptoConfigValidator.validate(base.copy(keySizeBits = bits,
                symmetricKey = KeyMaterial(ByteArray(bits / 8) { 11 })))
            val profile = HandshakeConfigValidator.validate(selected)
            val data = ByteArray(12345) { (it * 31).toByte() }
            val pool = Executors.newSingleThreadExecutor()
            try {
                ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { listener ->
                    val server = pool.submit(Callable {
                        listener.accept().use { socket ->
                            socket.soTimeout = 3000
                            val session = ServerHandshake(selected).perform(socket.getInputStream(), socket.getOutputStream())
                            SecureStreamSender(session, profile).send(data.inputStream(), socket.getOutputStream(), MediaResponseMetadata.full(data.size.toLong()))
                        }
                    })
                    Socket(InetAddress.getLoopbackAddress(), listener.localPort).use { socket ->
                        socket.soTimeout = 3000
                        val session = ProxyHandshake(selected).perform(socket.getInputStream(), socket.getOutputStream(), "sample.mp4")
                        val output = ByteArrayOutputStream()
                        assertEquals(data.size.toLong(), SecureStreamReceiver(session, profile).receive(socket.getInputStream(), output))
                        assertContentEquals(data, output.toByteArray())
                    }
                    assertEquals(data.size.toLong(), server.get(5, TimeUnit.SECONDS))
                }
            } finally { pool.shutdownNow() }
        }
    }
    private fun authenticated(vararg records: Pair<MessageType, ByteArray>): ByteArray {
        val protection = StreamRecordProtection(session(), settings)
        return try {
            serialize(records.mapIndexed { index, record -> protection.protect(record.first, 100L + index, record.second) })
        } finally { protection.destroy() }
    }

    @Test
    fun `test metadata is verified before callback and is not written into media`() {
        val data = byteArrayOf(1, 2, 3)
        val output = ByteArrayOutputStream()
        var callbacks = 0
        val bytes = SecureStreamReceiver(session(), settings).receive(wire(data).inputStream(), output) { metadata ->
            callbacks++
            assertEquals(0, output.size())
            assertEquals(3L, metadata.contentLength)
        }
        assertEquals(1, callbacks)
        assertEquals(3L, bytes)
        assertContentEquals(data, output.toByteArray())
    }

    @Test
    fun `test authenticated data before metadata and duplicate metadata are rejected`() {
        val dataFirst = authenticated(MessageType.MEDIA_BLOCK to StreamPayloadCodec.encodeData(byteArrayOf(1)))
        assertEquals("Dados antes dos metadados", assertFailsWith<IllegalArgumentException> { receive(dataFirst) }.message)
        val meta = StreamPayloadCodec.encodeMetadata(MediaResponseMetadata.full(1))
        val duplicate = authenticated(MessageType.MEDIA_BLOCK to meta, MessageType.MEDIA_BLOCK to meta)
        assertEquals("Metadados repetidos ou fora de ordem", assertFailsWith<IllegalArgumentException> { receive(duplicate) }.message)
    }

    @Test
    fun `test body longer or shorter than authenticated metadata cannot complete`() {
        val meta = StreamPayloadCodec.encodeMetadata(MediaResponseMetadata.full(2))
        val tooLong = authenticated(MessageType.MEDIA_BLOCK to meta,
            MessageType.MEDIA_BLOCK to StreamPayloadCodec.encodeData(byteArrayOf(1, 2, 3)))
        assertFailsWith<IllegalArgumentException> { receive(tooLong) }
        val tooShort = authenticated(MessageType.MEDIA_BLOCK to meta,
            MessageType.MEDIA_BLOCK to StreamPayloadCodec.encodeData(byteArrayOf(1)),
            MessageType.END_STREAM to StreamPayloadCodec.encodeEnd(EndStreamPayload(102, "a".repeat(64)), 64))
        val output = ByteArrayOutputStream()
        assertFailsWith<IllegalArgumentException> { receive(tooShort, output) }
        assertEquals(0, output.size())
    }

    @Test
    fun `test malformed authenticated metadata is rejected before callback`() {
        val malformed = StreamPayloadCodec.encodeMetadata(MediaResponseMetadata.full(2)).also {
            java.nio.ByteBuffer.wrap(it).putLong(12, 3) // full-response length differs from total length
        }
        var callback = false
        val output = ByteArrayOutputStream()
        val encoded = authenticated(MessageType.MEDIA_BLOCK to malformed)
        assertFailsWith<IllegalArgumentException> {
            SecureStreamReceiver(session(), settings).receive(encoded.inputStream(), output) { callback = true }
        }
        assertFalse(callback)
        assertEquals(0, output.size())
    }

    @Test
    fun `test unknown subtype and end before metadata are rejected`() {
        assertFailsWith<IllegalArgumentException> { receive(authenticated(MessageType.MEDIA_BLOCK to byteArrayOf(99))) }
        val end = StreamPayloadCodec.encodeEnd(EndStreamPayload(100, "a".repeat(64)), 64)
        assertFailsWith<IllegalArgumentException> { receive(authenticated(MessageType.END_STREAM to end)) }
    }

    @Test
    fun `test short source never sends successful end and long source stays bounded to selection`() {
        val output = ByteArrayOutputStream()
        assertFailsWith<EOFException> {
            SecureStreamSender(session(), settings).send(byteArrayOf(1).inputStream(), output, MediaResponseMetadata.full(2))
        }
        assertFailsWith<EOFException> { receive(output.toByteArray()) }
        val bounded = ByteArrayOutputStream()
        SecureStreamSender(session(), settings).send(byteArrayOf(1, 2, 3).inputStream(), bounded, MediaResponseMetadata.full(2))
        assertContentEquals(byteArrayOf(1, 2), receive(bounded.toByteArray()))
    }

}
