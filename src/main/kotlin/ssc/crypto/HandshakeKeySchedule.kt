package ssc.crypto

import ssc.config.dto.KeyMaterial

/** Key roles are distinct even when both participants start with the same PSK. */
data class ProtectionKeys(val key: KeyMaterial, val iv: KeyMaterial, val macKey: KeyMaterial? = null)
data class SessionKeys(val proxyToServer: ProtectionKeys, val serverToProxy: ProtectionKeys)

object HandshakeKeySchedule {
    /** CTR uses both configured independent secrets; AEAD keeps the original PSK schedule. */
    fun authenticationSecret(psk: ByteArray, macPsk: ByteArray?): ByteArray = try {
        if (macPsk == null) psk.copyOf()
        else expand(HandshakeCrypto.extract(macPsk, psk), "configured authentication root", byteArrayOf(), 32)
    } finally {
        psk.fill(0)
        macPsk?.fill(0)
    }

    fun clientHelloAuthentication(psk: ByteArray, clientRandom: ByteArray): ByteArray {
        val prk = HandshakeCrypto.extract(HandshakeCrypto.sha256(clientRandom), psk)
        return expand(prk, "client hello authentication", byteArrayOf(), 32)
    }

    fun serverHelloProtection(psk: ByteArray, clientRandom: ByteArray, serverRandom: ByteArray,
                              clientHelloHash: ByteArray, keyBytes: Int, ivBytes: Int, macBytes: Int = 0): ProtectionKeys {
        // serverRandom is public, fresh for every response, even if Type 1 is replayed.
        // It changes the bootstrap key AND IV; SRV is still encrypted inside Type 2.
        val prk = HandshakeCrypto.extract(HandshakeCrypto.sha256(clientRandom, serverRandom), psk)
        return protection(prk, "server hello", clientHelloHash, keyBytes, ivBytes, macBytes)
    }

    fun sessionSecret(psk: ByteArray, dhSecret: ByteArray, clientRandom: ByteArray,
                      srv: ByteArray, helloTranscriptHash: ByteArray): ByteArray {
        val authenticationRoot = HandshakeCrypto.extract(HandshakeCrypto.sha256(clientRandom, srv), psk)
        val combined = HandshakeCrypto.extract(authenticationRoot, dhSecret)
        return expand(combined, "handshake secret", helloTranscriptHash, 32)
    }

    fun clientFinishedProtection(secret: ByteArray, helloTranscriptHash: ByteArray, keyBytes: Int, ivBytes: Int, macBytes: Int = 0): ProtectionKeys =
        protection(secret, "client finished", helloTranscriptHash, keyBytes, ivBytes, macBytes)

    fun trafficKeys(secret: ByteArray, fullTranscriptHash: ByteArray, keyBytes: Int, ivBytes: Int, macBytes: Int = 0): SessionKeys = SessionKeys(
        protection(secret, "proxy to server traffic", fullTranscriptHash, keyBytes, ivBytes, macBytes),
        protection(secret, "server to proxy traffic", fullTranscriptHash, keyBytes, ivBytes, macBytes),
    )

    private fun protection(secret: ByteArray, role: String, context: ByteArray, keyBytes: Int, ivBytes: Int, macBytes: Int) = ProtectionKeys(
        KeyMaterial(expand(secret, "$role key", context, keyBytes)),
        KeyMaterial(expand(secret, "$role iv", context, ivBytes)),
        if (macBytes == 0) null else KeyMaterial(expand(secret, "$role mac key", context, macBytes)),
    )

    private fun expand(secret: ByteArray, label: String, context: ByteArray, size: Int): ByteArray {
        // Domain separation: a distinct label prevents one key role from reusing another's output.
        val info = "SSC-WA1/1:1/$label".toByteArray(Charsets.UTF_8) + byteArrayOf(0) + context
        return HandshakeCrypto.expand(secret, info, size)
    }
}
