package ssc.cryptoConfigLoader

import ssc.config.CryptoConfigLoader
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import java.nio.file.Files
import java.nio.file.Path
import java.util.Base64

const val PROXY__XML_PATH = "src/test/resources/config/proxycrypto.config"
const val STREAM_SERVER_XML_PATH = "src/test/resources/config/sservercrypto.config"

class cryptoConfigLoaderTest {

    @Test
    fun `test correct entities extraction from proxy xml file`() {
        val path = PROXY__XML_PATH

        val config = CryptoConfigLoader.load(path)

        assertNotNull(config)
        assertEquals("AES", config.algorithm)
        assertEquals("GCM", config.mode)
        assertNull(config.iv)
        assertEquals(96, config.ivSizeBits)
        assertNull(config.padding)
        assertEquals(256, config.keySizeBits)
        assertNotNull(config.symmetricKey)
        assertEquals(256, config.symmetricKey.sizeBits)
        assertNull(config.macAlgorithm)
        assertNull(config.macKey)
        assertNull(config.macKeySizeBits)
    }

    @Test
    fun `test correct entities extraction from stream server xml file`() {
        val path = STREAM_SERVER_XML_PATH

        val config = CryptoConfigLoader.load(path)

        assertNotNull(config)
        assertEquals("AES", config.algorithm)
        assertEquals("GCM", config.mode)
        assertNull(config.iv)
        assertEquals(96, config.ivSizeBits)
        assertNull(config.padding)
        assertEquals(256, config.keySizeBits)
        assertNotNull(config.symmetricKey)
        assertEquals(256, config.symmetricKey.sizeBits)
        assertNull(config.macAlgorithm)
        assertNull(config.macKey)
        assertNull(config.macKeySizeBits)
    }

    @Test
    fun `test key bytes are decoded from hex and base64`() {
        val expected = ByteArray(32) { 0x11 }
        val hexConfig = CryptoConfigLoader.load(PROXY__XML_PATH)
        assertContentEquals(expected, hexConfig.symmetricKey!!.copyBytes())
        val xml = fixture().replace("encoding=\"hex\"", "encoding=\"base64\"")
            .replace("11".repeat(32), Base64.getEncoder().encodeToString(expected))
        withXml(xml) { path ->
            assertContentEquals(expected, CryptoConfigLoader.load(path).symmetricKey!!.copyBytes())
        }
    }

    @Test
    fun `test malformed or ambiguous xml is rejected`() {
        val invalid = listOf(
            fixture().replace("<Mode>GCM</Mode>", ""),
            fixture().replace("<Mode>GCM</Mode>", "<Mode>GCM</Mode><Mode>CTR</Mode>"),
            fixture().replace("<Mode>GCM</Mode>", "<Wrapper><Mode>GCM</Mode></Wrapper>"),
            fixture().replace("<Mode>GCM</Mode>", "<Mode> </Mode>"),
            fixture().replace("<Keysize>256</Keysize>", "<Keysize>abc</Keysize>"),
            fixture().replace("<MACSuite>", "<MACSuiet>"),
            fixture().replace("unit=\"bits\"", "unit=\"bytes\""),
            fixture().replace("version=\"1.0\">", "version=\"2.0\">"),
            fixture().replace("ProxyCryptoConfig", "UnknownRoot"),
            fixture().replace("<Mode>GCM</Mode>", "<Mode><Nested>GCM</Nested></Mode>"),
            fixture().replace("<Mode>GCM</Mode>", "<Mode unexpected=\"value\">GCM</Mode>"),
            fixture().replace("<SymCipherSuite>", "<SymCipherSuite>unexpected text"),
            fixture().replace("encoding=\"hex\"", "encodng=\"hex\""),
            "<ProxyCryptoConfig>",
        )
        invalid.forEach { xml ->
            withXml(xml) { path -> assertFailsWith<IllegalArgumentException> { CryptoConfigLoader.load(path) } }
        }
    }

    @Test
    fun `test dtd and external entities are rejected`() {
        val xml = fixture().replace("<ProxyCryptoConfig version=\"1.0\">",
            "<!DOCTYPE ProxyCryptoConfig [<!ENTITY external SYSTEM 'file:///unused'>]>" +
                "<ProxyCryptoConfig version=\"1.0\">")
        withXml(xml) { path -> assertFailsWith<IllegalArgumentException> { CryptoConfigLoader.load(path) } }
    }

    @Test
    fun `test invalid encoded keys do not appear in errors`() {
        for ((encoding, secret) in listOf("hex" to "NOT_A_SECRET_KEY", "base64" to "***SECRET***", "unknown" to "SECRET")) {
            val xml = fixture().replace("encoding=\"hex\"", "encoding=\"$encoding\"")
                .replace("11".repeat(32), secret)
            withXml(xml) { path ->
                val error = assertFailsWith<IllegalArgumentException> { CryptoConfigLoader.load(path) }
                assertFalse(error.message.orEmpty().contains(secret))
            }
        }
    }

    @Test
    fun `test oversized xml is rejected`() {
        withXml(" ".repeat(64 * 1024 + 1)) { path ->
            assertFailsWith<IllegalArgumentException> { CryptoConfigLoader.load(path) }
        }
    }

    @Test
    fun `test mac fields are extracted from their own section`() {
        val xml = fixture().replace("<Mode>GCM</Mode>", "<Mode>CTR</Mode>")
            .replace(">96</IVSize>", ">128</IVSize>")
            .replace("<MACSuite><Algorithm>NULL</Algorithm></MACSuite>",
                "<MACSuite><Algorithm>HMAC-SHA256</Algorithm></MACSuite>")
            .replace("<MacKey>NULL</MacKey>", "<MacKey encoding=\"hex\">" + "22".repeat(32) + "</MacKey>")
            .replace("<MacKeySize>NULL</MacKeySize>", "<MacKeySize>256</MacKeySize>")
        withXml(xml) { path ->
            val config = CryptoConfigLoader.load(path)
            assertEquals("AES", config.algorithm)
            assertEquals("HMAC-SHA256", config.macAlgorithm)
            assertEquals(256, config.macKeySizeBits)
            assertContentEquals(ByteArray(32) { 0x22 }, config.macKey!!.copyBytes())
        }
    }

    @Test
    fun `test key material is redacted and cannot be mutated from outside`() {
        val config = CryptoConfigLoader.load(PROXY__XML_PATH)
        assertTrue(config.toString().contains("[REDACTED]"))
        val copy = config.symmetricKey!!.copyBytes()
        copy.fill(0)
        assertContentEquals(ByteArray(32) { 0x11 }, config.symmetricKey.copyBytes())
    }

    private fun fixture(): String = Files.readString(Path.of(PROXY__XML_PATH))

    private fun withXml(xml: String, block: (String) -> Unit) {
        val path = Files.createTempFile("crypto-loader-test-", ".xml")
        try {
            Files.writeString(path, xml)
            block(path.toString())
        } finally {
            Files.deleteIfExists(path)
        }
    }
}
