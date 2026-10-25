package ssc.config

import ssc.config.dto.CryptoConfig

/** Algorithm family and protection construction are different classifications. */
enum class CipherFamily { BLOCK_CIPHER, STREAM_CIPHER }
enum class ProtectionCategory { AEAD, ENCRYPT_THEN_MAC }
enum class NonceRequirement { UNIQUE_PER_KEY, DISJOINT_COUNTER_RANGES_PER_KEY }

/** Protocol profiles planned for incremental implementation; this is not a cipher engine. */
enum class CipherSuite(
    val algorithm: String,
    val mode: String,
    val transformation: String,
    val family: CipherFamily,
    val protection: ProtectionCategory,
    val keySizesBits: Set<Int>,
    val ivSizeBits: Int,
    val nonceRequirement: NonceRequirement,
) {
    AES_GCM("AES", "GCM", "AES/GCM/NoPadding", CipherFamily.BLOCK_CIPHER,
        ProtectionCategory.AEAD, setOf(128, 192, 256), 96, NonceRequirement.UNIQUE_PER_KEY),
    CHACHA20_POLY1305("ChaCha20", "Poly1305", "ChaCha20-Poly1305", CipherFamily.STREAM_CIPHER,
        ProtectionCategory.AEAD, setOf(256), 96, NonceRequirement.UNIQUE_PER_KEY),
    AES_CTR_HMAC("AES", "CTR", "AES/CTR/NoPadding", CipherFamily.BLOCK_CIPHER,
        ProtectionCategory.ENCRYPT_THEN_MAC, setOf(128, 192, 256), 128,
        NonceRequirement.DISJOINT_COUNTER_RANGES_PER_KEY);

    companion object {
        fun resolve(algorithm: String, mode: String): CipherSuite =
            entries.singleOrNull { it.algorithm.equals(algorithm, true) && it.mode.equals(mode, true) }
                ?: throw IllegalArgumentException("Suite não suportada; opções: AES/GCM, ChaCha20/Poly1305 e AES/CTR com HMAC")
    }
}

enum class MacSuite(val configName: String, val jcaName: String, val minimumKeySizeBits: Int) {
    HMAC_SHA256("HMAC-SHA256", "HmacSHA256", 256),
    HMAC_SHA384("HMAC-SHA384", "HmacSHA384", 384),
    HMAC_SHA512("HMAC-SHA512", "HmacSHA512", 512);

    companion object {
        fun resolve(name: String): MacSuite = entries.singleOrNull {
            it.configName.equals(name, true) || it.jcaName.equals(name, true)
        } ?: throw IllegalArgumentException("MAC não suportado; opções: HMAC-SHA256, HMAC-SHA384 e HMAC-SHA512")
    }
}

/** The local policy passed validation; remote compatibility and runtime nonce safety are separate. */
data class ValidatedCryptoConfig(
    val config: CryptoConfig,
    val suite: CipherSuite,
    val macSuite: MacSuite?,
)
