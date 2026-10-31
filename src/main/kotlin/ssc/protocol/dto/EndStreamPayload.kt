package ssc.protocol.dto

data class EndStreamPayload(val sequence: Long, val randomString: String) : MessagePayload {
    override val messageType = MessageType.END_STREAM
}
