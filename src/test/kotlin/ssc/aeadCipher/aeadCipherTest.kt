package ssc.aeadCipher

import ssc.config.CipherSuite
import ssc.crypto.AeadCipher
import java.util.HexFormat
import javax.crypto.AEADBadTagException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class aeadCipherTest {
    private fun hex(value: String) = HexFormat.of().parseHex(value)

    @Test
    fun `test chacha20 poly1305 matches RFC 8439 section 2 point 8 point 2`() {
        val cipher = AeadCipher(CipherSuite.CHACHA20_POLY1305, 128)
        val key = ByteArray(32) { (0x80 + it).toByte() }
        val nonce = hex("070000004041424344454647")
        val aad = hex("50515253c0c1c2c3c4c5c6c7")
        val plaintext = hex("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a20496620492063" +
            "6f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" +
            "637265656e20776f756c642062652069742e")
        val expected = hex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
            "3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691")
        assertContentEquals(expected, cipher.encrypt(plaintext, key, nonce, aad))
        assertContentEquals(plaintext, cipher.decrypt(expected, key, nonce, aad))
    }

    @Test
    fun `test aes gcm matches known zero key nonce and block vector`() {
        val cipher = AeadCipher(CipherSuite.AES_GCM, 128)
        val expected = hex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")
        assertContentEquals(expected, cipher.encrypt(ByteArray(16), ByteArray(16), ByteArray(12), byteArrayOf()))
        assertContentEquals(ByteArray(16), cipher.decrypt(expected, ByteArray(16), ByteArray(12), byteArrayOf()))
    }

    @Test
    fun `test both suites reject altered ciphertext aad nonce or key`() {
        for (suite in listOf(CipherSuite.AES_GCM, CipherSuite.CHACHA20_POLY1305)) {
            val cipher = AeadCipher(suite, 128)
            cipher.checkAvailability(256)
            val key = ByteArray(32) { 1 }
            val nonce = ByteArray(12) { 2 }
            val aad = byteArrayOf(3)
            val encrypted = cipher.encrypt(byteArrayOf(4, 5, 6), key, nonce, aad)
            assertEquals(3 + 16, encrypted.size)
            assertFailsWith<AEADBadTagException> {
                cipher.decrypt(encrypted.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }, key, nonce, aad)
            }
            assertFailsWith<AEADBadTagException> { cipher.decrypt(encrypted, key, nonce, byteArrayOf(7)) }
            assertFailsWith<AEADBadTagException> { cipher.decrypt(encrypted, key, ByteArray(12) { 8 }, aad) }
            assertFailsWith<AEADBadTagException> { cipher.decrypt(encrypted, ByteArray(32) { 9 }, nonce, aad) }
        }
    }

    @Test
    fun `test invalid suite tag nonce and derived key parameters are rejected`() {
        assertFailsWith<IllegalArgumentException> { AeadCipher(CipherSuite.AES_CTR_HMAC, 128) }
        for (suite in listOf(CipherSuite.AES_GCM, CipherSuite.CHACHA20_POLY1305)) {
            assertFailsWith<IllegalArgumentException> { AeadCipher(suite, 64) }
            val cipher = AeadCipher(suite, 128)
            assertFailsWith<IllegalArgumentException> { cipher.encrypt(byteArrayOf(), ByteArray(32), ByteArray(16), byteArrayOf()) }
            assertFailsWith<IllegalArgumentException> { cipher.decrypt(ByteArray(15), ByteArray(32), ByteArray(12), byteArrayOf()) }
        }
        assertFailsWith<IllegalArgumentException> {
            AeadCipher(CipherSuite.CHACHA20_POLY1305, 128).encrypt(byteArrayOf(), ByteArray(16), ByteArray(12), byteArrayOf())
        }
    }

    @Test
    fun `test selected suites cannot interpret each others ciphertext`() {
        val aes = AeadCipher(CipherSuite.AES_GCM, 128)
        val chacha = AeadCipher(CipherSuite.CHACHA20_POLY1305, 128)
        val key = ByteArray(32) { 1 }
        val nonce = ByteArray(12) { 2 }
        val aad = byteArrayOf(3)
        val encrypted = aes.encrypt(byteArrayOf(4), key, nonce, aad)
        assertFailsWith<AEADBadTagException> { chacha.decrypt(encrypted, key, nonce, aad) }
    }
}
