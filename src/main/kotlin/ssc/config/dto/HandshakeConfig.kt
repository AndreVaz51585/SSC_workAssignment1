package ssc.config.dto

/** Project extension to the assignment XML: explicit settings for the authenticated key exchange. */
data class HandshakeConfig(
    val dhGroup: String,
    val kdf: String,
    val authentication: String,
    val tagSizeBits: Int,
    val randomSizeBytes: Int,
    val maxPayloadBytes: Int,
    val socketTimeoutMillis: Int,
    val maxStreamRecords: Long,
)
