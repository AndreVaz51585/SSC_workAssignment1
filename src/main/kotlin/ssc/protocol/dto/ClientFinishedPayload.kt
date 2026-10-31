package ssc.protocol.dto

/** Type 3 reference fields: SEQZ || R || MEDIA. Protection is applied outside this object. */
data class ClientFinishedPayload(
    val sequence: Long,
    val challengeResponse: ByteArray,
    val media: String,
    val rangeHeader: String? = null,
) : MessagePayload {
    override val messageType: MessageType = MessageType.CLIENT_FINISHED
}
