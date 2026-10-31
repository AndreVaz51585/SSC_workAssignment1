package ssc.config

import ssc.config.dto.CryptoConfig


/** Algorithm family and protection construction are different classifications. */
enum class CipherFamily { BLOCK_CIPHER, STREAM_CIPHER }
enum class ProtectionCategory { AEAD, ENCRYPT_THEN_MAC }
enum class NonceRequirement { UNIQUE_PER_KEY, DISJOINT_COUNTER_RANGES_PER_KEY }

/** Supported AEAD and Encrypt-then-MAC profiles; execution belongs to the crypto adapter. */
enum class CipherSuite(
    val algorithm: String,
    val mode: String,
    val transformation: String,
    val family: CipherFamily,
    val protection: ProtectionCategory,
    val keySizesBits: Set<Int>,
    val ivSizeBits: Int,
    val nonceRequirement: NonceRequirement,
    val tagSizesBits: Set<Int>,
) {
    AES_GCM("AES", "GCM", "AES/GCM/NoPadding", CipherFamily.BLOCK_CIPHER,
        ProtectionCategory.AEAD, setOf(128, 192, 256), 96, NonceRequirement.UNIQUE_PER_KEY, setOf(128)),
    CHACHA20_POLY1305("ChaCha20", "Poly1305", "ChaCha20-Poly1305", CipherFamily.STREAM_CIPHER,
        ProtectionCategory.AEAD, setOf(256), 96, NonceRequirement.UNIQUE_PER_KEY, setOf(128)),
    AES_CTR_HMAC("AES", "CTR", "AES/CTR/NoPadding", CipherFamily.BLOCK_CIPHER,
        ProtectionCategory.ENCRYPT_THEN_MAC, setOf(128, 192, 256), 128,
        NonceRequirement.DISJOINT_COUNTER_RANGES_PER_KEY, emptySet());

    companion object {
        fun resolve(algorithm: String, mode: String): CipherSuite =
            entries.singleOrNull { it.algorithm.equals(algorithm, true) && it.mode.equals(mode, true) }
                ?: throw IllegalArgumentException("Suite não suportada; opções: AES/GCM, ChaCha20/Poly1305 e AES/CTR com HMAC")
    }
}

enum class MacSuite(val configName: String, val jcaName: String, val minimumKeySizeBits: Int, val tagSizeBits: Int) {
    HMAC_SHA256("HMAC-SHA256", "HmacSHA256", 256, 256),
    HMAC_SHA384("HMAC-SHA384", "HmacSHA384", 384, 384),
    HMAC_SHA512("HMAC-SHA512", "HmacSHA512", 512, 512);

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
