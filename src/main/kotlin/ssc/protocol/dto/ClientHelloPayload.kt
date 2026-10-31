package ssc.protocol.dto

/** Type 1: assignment sequence/proposal plus fields planned for authenticated ephemeral DH. */
data class ClientHelloPayload(
    val sequence: Long,
    val proposedConfig: ProposedCryptoConfig,
    val dhPublicKey: ByteArray,
    val clientRandom: ByteArray, // usado para acrescentar contexto à sessão.
    val authenticationTag: ByteArray,
) : MessagePayload {
    override val messageType: MessageType = MessageType.CLIENT_HELLO
}


// temos que  Proxy Z = DH(Kpriv, KpubServer)
// e          Server Z = DH(Kpriv, KpubProxy)
// A partir daqui as chaves de sessão são deriviadas de Z
