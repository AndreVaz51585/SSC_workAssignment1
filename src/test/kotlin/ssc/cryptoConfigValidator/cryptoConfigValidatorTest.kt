package ssc.cryptoConfigValidator

import ssc.config.CipherFamily
import ssc.config.CipherSuite
import ssc.config.CryptoConfigLoader
import ssc.config.CryptoConfigValidator
import ssc.config.MacSuite
import ssc.config.NonceRequirement
import ssc.config.ProtectionCategory
import ssc.config.dto.CryptoConfig
import ssc.config.dto.KeyMaterial
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class cryptoConfigValidatorTest {
    private fun aesGcm(bits: Int = 256) = CryptoConfig(
        algorithm = "AES", mode = "GCM", iv = null, ivSizeBits = 96, padding = null,
        macAlgorithm = null, symmetricKey = KeyMaterial(ByteArray(bits / 8) { 0x11 }),
        keySizeBits = bits, macKey = null, macKeySizeBits = null,
    )

    private fun aesCtr(mac: MacSuite = MacSuite.HMAC_SHA256) = aesGcm().copy(
        mode = "CTR", ivSizeBits = 128, macAlgorithm = mac.configName,
        macKey = KeyMaterial(ByteArray(mac.minimumKeySizeBits / 8) { 0x22 }),
        macKeySizeBits = mac.minimumKeySizeBits,
    )

    @Test
    fun `test both xml fixtures pass local configuration validation`() {
        for (name in listOf("proxycrypto", "sservercrypto")) {
            val config = CryptoConfigLoader.load("src/test/resources/config/$name.config")
            assertEquals(CipherSuite.AES_GCM, CryptoConfigValidator.validate(config).suite)
        }
    }

    @Test
    fun `test aes gcm accepts all planned aes key sizes`() {
        for (bits in listOf(128, 192, 256)) {
            val result = CryptoConfigValidator.validate(aesGcm(bits))
            assertEquals(CipherSuite.AES_GCM, result.suite)
            assertEquals(ProtectionCategory.AEAD, result.suite.protection)
            assertEquals(CipherFamily.BLOCK_CIPHER, result.suite.family)
            assertNull(result.macSuite)
        }
    }

    @Test
    fun `test chacha20 poly1305 is a stream cipher with integrated authentication`() {
        val config = aesGcm().copy(algorithm = "ChaCha20", mode = "Poly1305")
        val result = CryptoConfigValidator.validate(config)
        assertEquals(CipherSuite.CHACHA20_POLY1305, result.suite)
        assertEquals(CipherFamily.STREAM_CIPHER, result.suite.family)
        assertEquals(ProtectionCategory.AEAD, result.suite.protection)
        assertEquals(NonceRequirement.UNIQUE_PER_KEY, result.suite.nonceRequirement)
    }

    @Test
    fun `test ctr accepts each planned hmac and aes key size`() {
        for (mac in MacSuite.entries) {
            for (bits in listOf(128, 192, 256)) {
                val base = aesGcm(bits)
                val config = aesCtr(mac).copy(symmetricKey = base.symmetricKey, keySizeBits = bits)
                val result = CryptoConfigValidator.validate(config)
                assertEquals(CipherSuite.AES_CTR_HMAC, result.suite)
                assertEquals(mac, result.macSuite)
                assertEquals(ProtectionCategory.ENCRYPT_THEN_MAC, result.suite.protection)
                assertEquals(NonceRequirement.DISJOINT_COUNTER_RANGES_PER_KEY, result.suite.nonceRequirement)
            }
        }
    }

    @Test
    fun `test names accept case differences and jca mac spelling`() {
        val config = aesCtr().copy(algorithm = "aes", mode = "ctr", padding = "NoPadding", macAlgorithm = "HmacSHA256")
        assertEquals(MacSuite.HMAC_SHA256, CryptoConfigValidator.validate(config).macSuite)
    }

    @Test
    fun `test incompatible algorithm and mode pairs are rejected`() {
        for (config in listOf(
            aesGcm().copy(algorithm = "RC6"), aesGcm().copy(mode = "ECB"),
            aesGcm().copy(mode = "CBC"), aesGcm().copy(mode = "Poly1305"),
            aesGcm().copy(algorithm = "ChaCha20"), aesGcm().copy(mode = ""),
        )) reject(config)
    }

    @Test
    fun `test padding is checked for every suite`() {
        val suites = listOf(aesGcm(), aesGcm().copy(algorithm = "ChaCha20", mode = "Poly1305"), aesCtr())
        suites.forEach { reject(it.copy(padding = "PKCS5Padding")) }
    }

    @Test
    fun `test nonce size is checked per suite rather than globally`() {
        reject(aesGcm().copy(ivSizeBits = 128))
        reject(aesGcm().copy(algorithm = "ChaCha20", mode = "Poly1305", ivSizeBits = 128))
        reject(aesCtr().copy(ivSizeBits = 96))
        for (bits in listOf(null, 0, -96)) reject(aesGcm().copy(ivSizeBits = bits))
    }

    @Test
    fun `test fixed iv is rejected for every suite by protocol policy`() {
        for (config in listOf(aesGcm(), aesCtr(), aesGcm().copy(algorithm = "ChaCha20", mode = "Poly1305"))) {
            reject(config.copy(iv = "00".repeat(config.ivSizeBits!! / 8)))
        }
    }

    @Test
    fun `test key lengths must match the suite and declared size`() {
        reject(aesGcm().copy(keySizeBits = 64))
        reject(aesGcm().copy(symmetricKey = KeyMaterial(ByteArray(16))))
        reject(aesGcm().copy(symmetricKey = null))
        reject(aesGcm(128).copy(algorithm = "ChaCha20", mode = "Poly1305"))
    }

    @Test
    fun `test aead rejects each separate mac field`() {
        for (base in listOf(aesGcm(), aesGcm().copy(algorithm = "ChaCha20", mode = "Poly1305"))) {
            reject(base.copy(macAlgorithm = "HMAC-SHA256"))
            reject(base.copy(macKey = KeyMaterial(ByteArray(32))))
            reject(base.copy(macKeySizeBits = 256))
        }
    }

    @Test
    fun `test ctr requires supported hmac and complete matching key fields`() {
        reject(aesCtr().copy(macAlgorithm = null))
        reject(aesCtr().copy(macAlgorithm = "SHA256"))
        reject(aesCtr().copy(macKey = null))
        reject(aesCtr().copy(macKeySizeBits = null))
        reject(aesCtr().copy(macKeySizeBits = 512))
        reject(aesCtr().copy(macKey = KeyMaterial(ByteArray(31)), macKeySizeBits = 248))
        reject(aesCtr().copy(macKeySizeBits = 257))
    }

    @Test
    fun `test hmac minimum key length is an explicit per mac policy`() {
        for (mac in MacSuite.entries) {
            val bits = mac.minimumKeySizeBits - 8
            reject(aesCtr(mac).copy(macKey = KeyMaterial(ByteArray(bits / 8)), macKeySizeBits = bits))
        }
        val larger = aesCtr().copy(macKey = KeyMaterial(ByteArray(64)), macKeySizeBits = 512)
        assertEquals(MacSuite.HMAC_SHA256, CryptoConfigValidator.validate(larger).macSuite)
    }

    @Test
    fun `test encryption and mac bootstrap secrets must differ`() {
        reject(aesCtr().copy(macKey = KeyMaterial(ByteArray(32) { 0x11 })))
    }

    private fun reject(config: CryptoConfig) {
        assertFailsWith<IllegalArgumentException> { CryptoConfigValidator.validate(config) }
    }
}
