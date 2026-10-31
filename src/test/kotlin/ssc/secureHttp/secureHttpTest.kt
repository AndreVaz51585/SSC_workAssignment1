package ssc.secureHttp

import ssc.HttpUtil
import java.nio.file.Files
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

import ssc.support.ProtocolTestSupport.withHttpServers as withServers
import ssc.support.ProtocolTestSupport.get

class secureHttpTest {
    @Test
    fun `test full mp4 response delivers only exact decrypted media bytes`() = withServers { port, _, data ->
        val response = get(port, "/video/sample.mp4")
        assertEquals(200, response.status)
        assertEquals("video/mp4", response.headers["content-type"])
        assertEquals(data.size.toString(), response.headers["content-length"])
        assertEquals("bytes", response.headers["accept-ranges"])
        assertFalse("content-range" in response.headers)
        assertContentEquals(data, response.body)
    }

    @Test
    fun `test browser range closed open suffix and oversized end map to exact bytes`() = withServers { port, _, data ->
        for ((range, start, end) in listOf(
            Triple("bytes=1000-1999", 1000, 1999),
            Triple("bytes=16000-", 16000, data.lastIndex),
            Triple("bytes=-500", data.size - 500, data.lastIndex),
            Triple("bytes=16000-999999999999999999999", 16000, data.lastIndex),
        )) {
            val response = get(port, "/video/sample.mp4", "Range: $range")
            assertEquals(206, response.status)
            assertEquals("bytes $start-$end/${data.size}", response.headers["content-range"])
            assertEquals((end - start + 1).toString(), response.headers["content-length"])
            assertContentEquals(data.copyOfRange(start, end + 1), response.body)
        }
    }

    @Test
    fun `test unsatisfiable range is an authenticated 416 response`() = withServers { port, _, data ->
        val response = get(port, "/video/sample.mp4", "Range: bytes=${data.size}-")
        assertEquals(416, response.status)
        assertEquals("bytes */${data.size}", response.headers["content-range"])
        assertEquals("0", response.headers["content-length"])
        assertTrue(response.body.isEmpty())
    }

    @Test
    fun `test multipart invalid and if range requests conservatively return full content`() = withServers { port, _, data ->
        for (headers in listOf(arrayOf("Range: bytes=0-1,5-6"), arrayOf("Range: bytes=10-1"),
            arrayOf("Range: bytes=0-99", "If-Range: \"unknown-validator\""))) {
            val response = get(port, "/video/sample.mp4", *headers)
            assertEquals(200, response.status)
            assertContentEquals(data, response.body)
        }
    }

    @Test
    fun `test page catalog unicode names empty media and missing resources`() = withServers { port, _, data ->
        val page = get(port, "/")
        assertEquals(200, page.status)
        assertTrue(page.body.toString(Charsets.UTF_8).contains("<video"))
        val catalog = get(port, "/catalog")
        assertEquals(200, catalog.status)
        assertEquals("text/plain; charset=utf-8", catalog.headers["content-type"])
        assertTrue(catalog.body.toString(Charsets.UTF_8).contains(HttpUtil.encodeName("música de teste.mp4")))
        assertContentEquals(data, get(port, "/video/" + HttpUtil.encodeName("música de teste.mp4")).body)
        val empty = get(port, "/video/empty.mp4")
        assertEquals(200, empty.status)
        assertEquals("0", empty.headers["content-length"])
        assertTrue(empty.body.isEmpty())
        assertEquals(404, get(port, "/video/missing.mp4").status)
        assertEquals(404, get(port, "/unknown").status)
    }

    @Test
    fun `test traversal and symlink outside media root are not served or listed`() = withServers { port, root, _ ->
        val outside = Files.createTempFile("outside-media-test-", ".mp4")
        try {
            Files.write(outside, byteArrayOf(1, 2, 3))
            Files.createSymbolicLink(root.resolve("escape.mp4"), outside)
            assertEquals(404, get(port, "/video/escape.mp4").status)
            assertEquals(404, get(port, "/video/..%2F${outside.fileName}").status)
            assertFalse(get(port, "/catalog").body.toString(Charsets.UTF_8).contains("escape.mp4"))
        } finally { Files.deleteIfExists(outside) }
    }

    @Test
    fun `test duplicate range and oversized headers are rejected`() = withServers { port, _, _ ->
        assertEquals(400, get(port, "/video/sample.mp4", "Range: bytes=0-9", "Range: bytes=10-19").status)
        assertEquals(400, get(port, "/video/sample.mp4", "X-Large: " + "x".repeat(9000)).status)
    }

    @Test
    fun `test concurrent range requests remain independent`() = withServers { port, _, data ->
        val pool = Executors.newFixedThreadPool(4)
        try {
            val results = (0 until 8).map { i -> pool.submit(Callable {
                val start = i * 1000
                val response = get(port, "/video/sample.mp4", "Range: bytes=$start-${start + 499}")
                assertEquals(206, response.status)
                assertContentEquals(data.copyOfRange(start, start + 500), response.body)
            }) }
            results.forEach { it.get(10, TimeUnit.SECONDS) }
        } finally { pool.shutdownNow() }
    }

    @Test
    fun `test all selectable xml profiles deliver full media ranges and catalog over real http`() {
        for (profile in listOf("aes128-gcm","aes192-gcm","aes256-gcm","chacha20-poly1305","aes128-ctr-hmac-sha256","aes192-ctr-hmac-sha256","aes256-ctr-hmac-sha256","aes256-ctr-hmac-sha384","aes256-ctr-hmac-sha512")) {
            withServers(profile = profile) { port, _, data ->
                assertContentEquals(data, get(port, "/video/sample.mp4").body)
                val range = get(port, "/video/sample.mp4", "Range: bytes=1000-1999")
                assertEquals(206, range.status)
                assertContentEquals(data.copyOfRange(1000, 2000), range.body)
                assertEquals(200, get(port, "/catalog").status)
                assertEquals(416, get(port, "/video/sample.mp4", "Range: bytes=${data.size}-").status)
            }
        }
    }

    @Test
    fun `test incompatible aes and chacha profiles fail before http media without fallback`() {
        withServers(profile = "chacha20-poly1305", originProfile = "aes256-gcm") { port, _, _ ->
            val response = get(port, "/video/sample.mp4")
            assertEquals(502, response.status)
            assertTrue(response.body.isEmpty())
        }
    }


}
