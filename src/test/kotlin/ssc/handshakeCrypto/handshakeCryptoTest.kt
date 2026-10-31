package ssc.handshakeCrypto

import ssc.config.CipherSuite
import ssc.crypto.AeadCipher
import ssc.crypto.HandshakeCrypto
import ssc.crypto.HandshakeKeySchedule
import java.util.HexFormat
import javax.crypto.AEADBadTagException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith

class handshakeCryptoTest {
    private fun hex(value: String) = HexFormat.of().parseHex(value)

    @Test
    fun `test hkdf sha256 matches RFC 5869 test case one`() {
        val ikm = ByteArray(22) { 0x0b }
        val salt = hex("000102030405060708090a0b0c")
        val info = hex("f0f1f2f3f4f5f6f7f8f9")
        val prk = HandshakeCrypto.extract(salt, ikm)
        assertContentEquals(hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"), prk)
        assertContentEquals(hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
            HandshakeCrypto.expand(prk, info, 42))
    }

    @Test
    fun `test hkdf sha256 handles omitted salt RFC 5869 case three`() {
        val prk = HandshakeCrypto.extract(byteArrayOf(), ByteArray(22) { 0x0b })
        assertContentEquals(hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"), prk)
        assertContentEquals(hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"),
            HandshakeCrypto.expand(prk, byteArrayOf(), 42))
    }

    @Test
    fun `test gcm authenticates ciphertext and cleartext associated data`() {
        val key = ByteArray(32) { 1 }
        val iv = ByteArray(12) { 2 }
        val aad = "header".toByteArray()
        val plaintext = "payload".toByteArray()
        val cipher = AeadCipher(CipherSuite.AES_GCM, 128)
        val encrypted = cipher.encrypt(plaintext, key, iv, aad)
        assertContentEquals(plaintext, cipher.decrypt(encrypted, key, iv, aad))
        assertFailsWith<AEADBadTagException> {
            cipher.decrypt(encrypted.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }, key, iv, aad)
        }
        assertFailsWith<AEADBadTagException> {
            cipher.decrypt(encrypted, key, iv, "changed header".toByteArray())
        }
    }

    @Test
    fun `test key roles and server randomness produce distinct keys`() {
        val secret = ByteArray(32) { 1 }
        val context = ByteArray(32) { 2 }
        val traffic = HandshakeKeySchedule.trafficKeys(secret, context, 32, 12)
        val finished = HandshakeKeySchedule.clientFinishedProtection(secret, context, 32, 12)
        assertFalse(traffic.proxyToServer.key.copyBytes().contentEquals(traffic.serverToProxy.key.copyBytes()))
        assertFalse(traffic.proxyToServer.key.copyBytes().contentEquals(finished.key.copyBytes()))
        val first = HandshakeKeySchedule.serverHelloProtection(secret, context, ByteArray(32) { 3 }, context, 32, 12)
        val second = HandshakeKeySchedule.serverHelloProtection(secret, context, ByteArray(32) { 4 }, context, 32, 12)
        assertFalse(first.key.copyBytes().contentEquals(second.key.copyBytes()))
        assertFalse(first.iv.copyBytes().contentEquals(second.iv.copyBytes()))
    }

    @Test
    fun `test hkdf refuses output beyond RFC limit`() {
        assertFailsWith<IllegalArgumentException> { HandshakeCrypto.expand(ByteArray(32), byteArrayOf(), 255 * 32 + 1) }
    }
}
