package ssc.protocol.dto

data class MessageHeader(
    val version : Int = 1, // 2 bytes
    val release : Int = 1 , // 2 bytes
    val message : MessageType, // 1 byte
    val payloadLength : Int // 4 bytes
)
