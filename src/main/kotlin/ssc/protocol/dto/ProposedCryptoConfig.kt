package ssc.protocol.dto

/** Public negotiation parameters only. Local PSK and MAC key material must never be included. */
data class ProposedCryptoConfig(
    val algorithm: String,
    val mode: String,
    val ivSizeBits: Int,
    val padding: String?,
    val keySizeBits: Int,
    val macAlgorithm: String?,
    val macKeySizeBits: Int?,
    val dhGroup: String,
    val kdf: String,
    val handshakeAuthentication: String,
    val tagSizeBits: Int,
    val randomSizeBytes: Int,
)
