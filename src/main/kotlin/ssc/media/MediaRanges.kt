package ssc.media

import ssc.protocol.dto.MediaResponseMetadata

/** Single byte range. Unsupported/malformed/multipart ranges are ignored (full 200 response). */
object MediaRanges {
    private val singleRange = Regex("bytes=\\s*([0-9]*)-([0-9]*)", RegexOption.IGNORE_CASE)

    fun response(total: Long, header: String?): MediaResponseMetadata {
        require(total >= 0)
        val full = MediaResponseMetadata.full(total)
        if (header == null) return full
        val match = singleRange.matchEntire(header.trim()) ?: return full
        val (first, last) = match.destructured
        if (first.isEmpty() && last.isEmpty()) return full
        // Saturation handles even very large decimal numerals without overflow or signed wrap.
        fun number(value: String) = value.trimStart('0').let {
            if (it.isEmpty()) 0L else it.toLongOrNull() ?: Long.MAX_VALUE
        }
        if (total == 0L) return full // RFC 9110 permits ignoring Range on an empty representation.
        val start: Long
        val end: Long
        if (first.isEmpty()) {
            val suffix = number(last)
            if (suffix == 0L) return unsatisfiable(total)
            start = if (suffix >= total) 0L else total - suffix
            end = total - 1
        } else {
            start = number(first)
            val requestedEnd = if (last.isEmpty()) Long.MAX_VALUE else number(last)
            if (requestedEnd < start) return full // Invalid range syntax/semantics: ignore it.
            if (start >= total) return unsatisfiable(total)
            end = minOf(requestedEnd, total - 1)
        }
        return MediaResponseMetadata(206, MediaResponseMetadata.VIDEO_TYPE, total,
            end - start + 1, start, end)
    }

    private fun unsatisfiable(total: Long) = MediaResponseMetadata(416, null, total, 0)
}
