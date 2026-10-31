package ssc.protocol.dto

/** Authenticated response description, not arbitrary HTTP headers supplied by the peer. */
data class MediaResponseMetadata(
    val statusCode: Int,
    val contentType: String?,
    val totalLength: Long?,
    val contentLength: Long,
    val rangeStart: Long? = null,
    val rangeEndInclusive: Long? = null,
    val acceptRanges: Boolean = true,
) {
    fun validate() {
        require(contentLength >= 0 && (totalLength == null || totalLength >= 0)) { "Comprimentos de media inválidos" }
        require(contentType == null || contentType == VIDEO_TYPE || contentType == CATALOG_TYPE) { "Content-Type não permitido" }
        when (statusCode) {
            200 -> {
                require(totalLength != null && contentLength == totalLength && contentType != null)
                require(rangeStart == null && rangeEndInclusive == null)
            }
            206 -> {
                require(acceptRanges && contentType == VIDEO_TYPE)
                require(totalLength != null && rangeStart != null && rangeEndInclusive != null)
                require(rangeStart >= 0 && rangeEndInclusive >= rangeStart && rangeEndInclusive < totalLength)
                require(contentLength == rangeEndInclusive - rangeStart + 1)
            }
            416 -> {
                require(acceptRanges && totalLength != null && contentLength == 0L && contentType == null)
                require(rangeStart == null && rangeEndInclusive == null)
            }
            400, 404 -> {
                require(contentLength == 0L && totalLength == null && contentType == null && !acceptRanges)
                require(rangeStart == null && rangeEndInclusive == null)
            }
            else -> throw IllegalArgumentException("Estado de media não permitido")
        }
    }

    companion object {
        const val VIDEO_TYPE = "video/mp4"
        const val CATALOG_TYPE = "text/plain; charset=utf-8"
        fun full(length: Long, contentType: String = VIDEO_TYPE, acceptRanges: Boolean = true) =
            MediaResponseMetadata(200, contentType, length, length, acceptRanges = acceptRanges)
        fun error(status: Int) = MediaResponseMetadata(status, null, null, 0, acceptRanges = false)
    }
}
