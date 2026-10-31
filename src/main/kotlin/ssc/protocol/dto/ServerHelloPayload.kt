package ssc.protocol.dto

data class ServerHelloPayload(
    val srv : ByteArray, // usado para acrescentar contexto à sessão
    val seqy : Long,
    val acceptedConfig : ProposedCryptoConfig,
    val dhPublicKey: ByteArray, // Diffie-Hellman chave publica para ser utilizada para estabelecer o shared-secret efemero da sessão.
    // No separate authenticationTag: the encrypted Type 2 envelope carries the GCM tag.
) : MessagePayload {
    override val messageType = MessageType.SERVER_HELLO
}
