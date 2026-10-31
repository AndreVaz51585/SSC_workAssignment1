package ssc.cryptoProfiles

import ssc.config.CipherSuite
import ssc.config.CryptoConfigLoader
import ssc.config.CryptoConfigValidator
import ssc.config.HandshakeConfigValidator
import ssc.config.dto.KeyMaterial
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class cryptoProfilesTest {
    private val profiles = listOf("aes128-gcm","aes192-gcm","aes256-gcm","chacha20-poly1305","aes128-ctr-hmac-sha256","aes192-ctr-hmac-sha256","aes256-ctr-hmac-sha256","aes256-ctr-hmac-sha384","aes256-ctr-hmac-sha512")

    @Test
    fun `test every named profile loads validates and has matching peer parameters`() {
        for (name in profiles) {
            val proxy = CryptoConfigValidator.validate(CryptoConfigLoader.load(
                "src/test/resources/config/profiles/$name/proxy.config", "ProxyCryptoConfig"))
            val server = CryptoConfigValidator.validate(CryptoConfigLoader.load(
                "src/test/resources/config/profiles/$name/server.config", "ServerCryptoConfig"))
            assertEquals(proxy.suite, server.suite)
            assertEquals(proxy.config.keySizeBits, server.config.keySizeBits)
            assertEquals(HandshakeConfigValidator.validate(proxy), HandshakeConfigValidator.validate(server))
            assertContentEquals(proxy.config.symmetricKey!!.copyBytes(), server.config.symmetricKey!!.copyBytes())
            val expected = when {
                name.contains("-ctr-") -> CipherSuite.AES_CTR_HMAC
                name.startsWith("aes") -> CipherSuite.AES_GCM
                else -> CipherSuite.CHACHA20_POLY1305
            }
            assertEquals(expected, proxy.suite)
            assertEquals(proxy.macSuite, server.macSuite)
            if (proxy.config.macKey != null) assertContentEquals(proxy.config.macKey.copyBytes(), server.config.macKey!!.copyBytes())
        }
    }

    @Test
    fun `test templates contain placeholders and cannot silently run with a public default psk`() {
        for (name in profiles) for (role in listOf("proxy", "server")) {
            val path = "config/profiles/$name/$role.config.example"
            assertEquals(true, Files.readString(Path.of(path)).contains("REPLACE_WITH_"))
            assertFailsWith<IllegalArgumentException> { CryptoConfigLoader.load(path) }
        }
    }

    @Test
    fun `test chacha configuration rejects wrong key nonce padding mac or tag`() {
        val base = CryptoConfigLoader.load("src/test/resources/config/profiles/chacha20-poly1305/proxy.config")
        for (invalid in listOf(
            base.copy(keySizeBits = 128, symmetricKey = KeyMaterial(ByteArray(16))),
            base.copy(ivSizeBits = 128), base.copy(iv = "001122"), base.copy(padding = "PKCS5Padding"),
            base.copy(macAlgorithm = "HMAC-SHA256", macKey = KeyMaterial(ByteArray(32)), macKeySizeBits = 256),
        )) assertFailsWith<IllegalArgumentException> { CryptoConfigValidator.validate(invalid) }
        for (tag in listOf(64, 96, 120)) assertFailsWith<IllegalArgumentException> {
            HandshakeConfigValidator.validate(CryptoConfigValidator.validate(base.copy(handshake = base.handshake!!.copy(tagSizeBits = tag))))
        }
    }
    @Test
    fun `test profile entity cannot be confused with its peer role`() {
        assertFailsWith<IllegalArgumentException> {
            CryptoConfigLoader.load("src/test/resources/config/profiles/aes256-gcm/proxy.config", "ServerCryptoConfig")
        }
    }

    @Test
    fun `test ctr configuration rejects unsafe padding iv mac key tag and missing fields`() {
        val base = CryptoConfigLoader.load("src/test/resources/config/profiles/aes256-ctr-hmac-sha256/proxy.config")
        for (invalid in listOf(base.copy(macAlgorithm = null), base.copy(macKey = null),
            base.copy(macKeySizeBits = 128), base.copy(macKey = base.symmetricKey),
            base.copy(iv = "001122"), base.copy(ivSizeBits = 96), base.copy(padding = "PKCS5Padding"))) {
            assertFailsWith<IllegalArgumentException> { CryptoConfigValidator.validate(invalid) }
        }
        assertFailsWith<IllegalArgumentException> {
            HandshakeConfigValidator.validate(CryptoConfigValidator.validate(base.copy(handshake = base.handshake!!.copy(tagSizeBits = 128))))
        }
    }

}
