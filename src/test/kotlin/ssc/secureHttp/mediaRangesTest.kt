package ssc.secureHttp

import ssc.media.MediaRanges
import kotlin.test.Test
import kotlin.test.assertEquals

class mediaRangesTest {
    @Test
    fun `test closed open suffix and clipped byte ranges`() {
        for ((header, start, end) in listOf(
            Triple("bytes=1000-1999", 1000L, 1999L),
            Triple("bytes=1000-", 1000L, 9999L),
            Triple("bytes=-500", 9500L, 9999L),
            Triple("bytes=9990-20000", 9990L, 9999L),
            Triple("bytes=-20000", 0L, 9999L),
            Triple("bytes=0-" + "9".repeat(200), 0L, 9999L),
        )) {
            val result = MediaRanges.response(10000, header)
            result.validate()
            assertEquals(206, result.statusCode)
            assertEquals(start, result.rangeStart)
            assertEquals(end, result.rangeEndInclusive)
            assertEquals(end - start + 1, result.contentLength)
        }
    }

    @Test
    fun `test unsatisfiable huge start and zero suffix are rejected`() {
        for (header in listOf("bytes=10000-", "bytes=-0", "bytes=" + "9".repeat(200) + "-")) {
            val result = MediaRanges.response(10000, header)
            result.validate()
            assertEquals(416, result.statusCode)
            assertEquals(0L, result.contentLength)
            assertEquals(10000L, result.totalLength)
        }
    }

    @Test
    fun `test invalid multipart and unsupported ranges are ignored without overflow`() {
        for (header in listOf(null, "bytes=10-1", "bytes=1-2,4-5", "items=0-5", "bytes=-", "bytes=abc-def")) {
            val result = MediaRanges.response(10000, header)
            result.validate()
            assertEquals(200, result.statusCode)
            assertEquals(10000L, result.contentLength)
        }
        val empty = MediaRanges.response(0, "bytes=0-")
        empty.validate()
        assertEquals(200, empty.statusCode)
        assertEquals(0L, empty.contentLength)
    }
}
