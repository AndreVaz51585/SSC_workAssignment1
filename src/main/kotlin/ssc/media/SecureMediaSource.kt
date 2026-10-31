package ssc.media

import ssc.HttpUtil
import ssc.protocol.dto.MediaResponseMetadata
import java.io.Closeable
import java.io.InputStream
import java.nio.channels.Channels
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.InvalidPathException
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.nio.file.StandardOpenOption

class MediaResponse(val metadata: MediaResponseMetadata, val body: InputStream) : Closeable {
    override fun close() = body.close()
}

/** Opens a bounded response selection; sender enforces contentLength without buffering the file. */
object SecureMediaSource {
    const val CATALOG = "/catalog" // Reserved protocol resource, never an absolute filesystem path.

    fun open(root: Path, media: String, rangeHeader: String?): MediaResponse {
        if (media == CATALOG) return catalog(root)
        // Direct files only, matching the catalog; reject encoded/decoded traversal and subdirectories.
        if (media.any { it == '/' || it == '\\' || it == '\u0000' } || media == "." || media == "..")
            return empty(404)
        val file = try {
            root.resolve(media).toRealPath()
        } catch (_: NoSuchFileException) {
            return empty(404)
        } catch (_: InvalidPathException) {
            return empty(400)
        }
        if (!file.startsWith(root) || !Files.isRegularFile(file) || !media.endsWith(".mp4", true)) return empty(404)
        val channel = FileChannel.open(file, StandardOpenOption.READ)
        try {
            val metadata = MediaRanges.response(channel.size(), rangeHeader)
            if (metadata.statusCode == 416) {
                channel.close()
                return MediaResponse(metadata, InputStream.nullInputStream())
            }
            channel.position(metadata.rangeStart ?: 0L)
            return MediaResponse(metadata, Channels.newInputStream(channel))
        } catch (exception: Exception) {
            channel.close()
            throw exception
        }
    }

    private fun catalog(root: Path): MediaResponse {
        val names = Files.list(root).use { entries ->
            entries.filter { file ->
                Files.isRegularFile(file) && file.fileName.toString().endsWith(".mp4", true) &&
                    file.toRealPath().startsWith(root)
            }.map { it.fileName.toString() }.sorted().toList()
        }
        val bytes = names.joinToString("\n") { HttpUtil.encodeName(it) }.toByteArray(Charsets.UTF_8)
        return MediaResponse(MediaResponseMetadata.full(bytes.size.toLong(), MediaResponseMetadata.CATALOG_TYPE, false),
            bytes.inputStream())
    }

    private fun empty(status: Int) = MediaResponse(MediaResponseMetadata.error(status), InputStream.nullInputStream())
}
