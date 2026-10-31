package ssc.messageProtection

import ssc.config.CipherSuite
import ssc.config.MacSuite
import ssc.crypto.HandshakeKeySchedule
import ssc.crypto.MessageProtection
import java.nio.ByteBuffer
import java.util.HexFormat
import javax.crypto.AEADBadTagException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class messageProtectionTest {
    private fun hex(s: String) = HexFormat.of().parseHex(s)

    @Test
    fun `test ctr encryption matches NIST SP 800 38A F5 first block with full hmac`() {
        val cipher = MessageProtection(CipherSuite.AES_CTR_HMAC, 256, MacSuite.HMAC_SHA256, 32)
        val key = hex("2b7e151628aed2a6abf7158809cf4f3c")
        val iv = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
        val plaintext = hex("6bc1bee22e409f96e93d7e117393172a")
        val macKey = ByteArray(32) { 22 }
        val encrypted = cipher.encrypt(plaintext, key, iv, byteArrayOf(1), macKey)
        assertContentEquals(hex("874d6191b620e3261bef6864990db6ce"), encrypted.copyOfRange(0, 16))
        assertEquals(16 + 32, encrypted.size)
        assertContentEquals(plaintext, cipher.decrypt(encrypted, key, iv, byteArrayOf(1), macKey))
    }

    @Test
    fun `test all ctr key and hmac sizes round trip and reject unauthenticated inputs`() {
        for (bits in listOf(128, 192, 256)) for (mac in MacSuite.entries) {
            val cipher = MessageProtection(CipherSuite.AES_CTR_HMAC, mac.tagSizeBits, mac, mac.minimumKeySizeBits / 8)
            cipher.checkAvailability(bits)
            val key = ByteArray(bits / 8) { 1 }
            val macKey = ByteArray(cipher.macKeyBytes) { 2 }
            val iv = cipher.nonce(ByteArray(16) { 3 }, 100)
            val aad = byteArrayOf(4, 5)
            val plaintext = ByteArray(1057) { it.toByte() }
            val encrypted = cipher.encrypt(plaintext, key, iv, aad, macKey)
            assertEquals(plaintext.size + mac.tagSizeBits / 8, encrypted.size)
            assertContentEquals(plaintext, cipher.decrypt(encrypted, key, iv, aad, macKey))
            for (offset in listOf(0, encrypted.lastIndex)) {
                val changed = encrypted.copyOf().also { it[offset] = (it[offset].toInt() xor 1).toByte() }
                assertFailsWith<AEADBadTagException> { cipher.decrypt(changed, key, iv, aad, macKey) }
            }
            assertFailsWith<AEADBadTagException> { cipher.decrypt(encrypted, key, iv, byteArrayOf(9), macKey) }
            assertFailsWith<AEADBadTagException> { cipher.decrypt(encrypted, key, cipher.nonce(ByteArray(16) { 3 }, 101), aad, macKey) }
            assertFailsWith<AEADBadTagException> { cipher.decrypt(encrypted, key, iv, aad, ByteArray(cipher.macKeyBytes) { 9 }) }
        }
    }

    @Test
    fun `test ctr allocates disjoint internal counter blocks across records`() {
        val cipher = MessageProtection(CipherSuite.AES_CTR_HMAC, 256, MacSuite.HMAC_SHA256, 32)
        val first = cipher.nonce(ByteArray(16) { 4 }, 100)
        val second = cipher.nonce(ByteArray(16) { 4 }, 101)
        assertEquals(0L, ByteBuffer.wrap(first, 8, 8).long)
        assertEquals(0L, ByteBuffer.wrap(second, 8, 8).long)
        assertFalse(first.copyOfRange(0, 8).contentEquals(second.copyOfRange(0, 8)))
        val used = HashSet<String>()
        for (sequence in 100L..105L) {
            val nonce = cipher.nonce(ByteArray(16) { 4 }, sequence)
            for (block in 0L..100L) {
                val counter = nonce.copyOf().also { ByteBuffer.wrap(it).putLong(8, block) }
                assertTrue(used.add(HexFormat.of().formatHex(counter)))
            }
        }
    }

    @Test
    fun `test mac keys are separated by role direction and configured secret`() {
        val secret = ByteArray(32) { 1 }
        val context = ByteArray(32) { 2 }
        val traffic = HandshakeKeySchedule.trafficKeys(secret, context, 32, 16, 32)
        val finished = HandshakeKeySchedule.clientFinishedProtection(secret, context, 32, 16, 32)
        assertFalse(traffic.serverToProxy.key.copyBytes().contentEquals(traffic.serverToProxy.macKey!!.copyBytes()))
        assertFalse(traffic.serverToProxy.macKey.copyBytes().contentEquals(traffic.proxyToServer.macKey!!.copyBytes()))
        assertFalse(traffic.serverToProxy.macKey.copyBytes().contentEquals(finished.macKey!!.copyBytes()))
        val root1 = HandshakeKeySchedule.authenticationSecret(ByteArray(32) { 1 }, ByteArray(32) { 2 })
        val root2 = HandshakeKeySchedule.authenticationSecret(ByteArray(32) { 1 }, ByteArray(32) { 3 })
        assertFalse(root1.contentEquals(root2))
    }

    @Test
    fun `test ctr rejects absent mac key wrong tag length and truncated tag`() {
        assertFailsWith<IllegalArgumentException> { MessageProtection(CipherSuite.AES_CTR_HMAC, 128, MacSuite.HMAC_SHA256, 32) }
        assertFailsWith<IllegalArgumentException> { MessageProtection(CipherSuite.AES_CTR_HMAC, 256, null, 32) }
        val cipher = MessageProtection(CipherSuite.AES_CTR_HMAC, 256, MacSuite.HMAC_SHA256, 32)
        assertFailsWith<IllegalArgumentException> { cipher.encrypt(byteArrayOf(), ByteArray(32), ByteArray(16), byteArrayOf()) }
        assertFailsWith<IllegalArgumentException> { cipher.decrypt(ByteArray(31), ByteArray(32), ByteArray(16), byteArrayOf(), ByteArray(32)) }
    }
}
