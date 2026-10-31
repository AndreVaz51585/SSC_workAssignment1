package ssc.protocol.dto

data class ProtocolMessage(
    val header : MessageHeader,
    val payload : ByteArray,
)
