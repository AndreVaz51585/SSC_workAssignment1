package ssc.protocol.dto

enum class MessageType(val code  : Int) {
    CLIENT_HELLO(1),
    SERVER_HELLO(2),
    CLIENT_FINISHED(3),
    MEDIA_BLOCK(4),
    END_STREAM(5),
    ERROR_ALERT(255)
}
