package ssc.protocol.dto

/** Plain media bytes; encryption belongs to the record layer, not to this DTO. */
data class MediaBlockPayload(val sequence: Long, val block: ByteArray) : MessagePayload {
    override val messageType = MessageType.MEDIA_BLOCK
}
