package ssc.protocol.handshake

import ssc.crypto.SessionKeys
import ssc.config.CipherSuite
import ssc.config.MacSuite

/** On the proxy, Type 3 has been sent; server acceptance is confirmed by its first protected record. */
class HandshakeSession(
    val keys: SessionKeys,
    val media: String,
    val firstMediaSequence: Long,
    sessionId: ByteArray,
    val rangeHeader: String? = null,
    val suite: CipherSuite,
    val macSuite: MacSuite? = null,
) {
    private val id = sessionId.copyOf()
    private var streamSenderClaimed = false
    private var streamReceiverClaimed = false

    @Synchronized
    internal fun claimStreamSender() {
        check(!streamSenderClaimed) { "Já existe um emissor de tráfego para esta sessão" }
        streamSenderClaimed = true
    }

    @Synchronized
    internal fun claimStreamReceiver() {
        check(!streamReceiverClaimed) { "Já existe um recetor de tráfego para esta sessão" }
        streamReceiverClaimed = true
    }

    fun sessionId(): ByteArray = id.copyOf()
    override fun toString(): String = "HandshakeSession(media=$media, firstMediaSequence=$firstMediaSequence, keys=[REDACTED])"
}
