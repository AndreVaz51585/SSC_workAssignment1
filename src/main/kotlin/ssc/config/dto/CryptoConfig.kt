package ssc.config.dto

/** Local configuration, before suite-specific validation. Not a negotiated session. */
data class CryptoConfig(
    val algorithm: String,
    val mode: String,
    val iv: String?,
    val ivSizeBits: Int?,
    val padding: String?,
    val macAlgorithm: String?,
    val symmetricKey: KeyMaterial?,
    val keySizeBits: Int,
    val macKey: KeyMaterial?,
    val macKeySizeBits: Int?,
)

/** Keeps decoded bytes out of generated toString() output and prevents mutation by callers. */
class KeyMaterial(bytes: ByteArray) {
    private val value = bytes.copyOf()
    val sizeBits: Int get() = value.size * 8
    fun copyBytes(): ByteArray = value.copyOf()
    override fun toString(): String = "[REDACTED]"
}
