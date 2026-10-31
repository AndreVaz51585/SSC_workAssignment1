package ssc.protocol.dto

/** Typed payload before encoding/protection; ProtocolMessage carries the resulting wire bytes. */
sealed interface MessagePayload {
    val messageType: MessageType
}
