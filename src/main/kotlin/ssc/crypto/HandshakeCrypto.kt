package ssc.crypto

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** SHA-256, HMAC and HKDF only. Suite-specific authenticated encryption lives in AeadCipher. */
object HandshakeCrypto {

    fun sha256(vararg parts: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").run {
        parts.forEach { update(it) }
        digest()
    }

    fun hmac(key: ByteArray, vararg parts: ByteArray): ByteArray = Mac.getInstance("HmacSHA256").run {
        init(SecretKeySpec(key, "HmacSHA256"))
        parts.forEach { update(it) }
        doFinal()
    }

    // RFC 5869: Extract mixes the input secret, Expand separates outputs by purpose/context.
    fun extract(salt: ByteArray, secret: ByteArray): ByteArray =
        hmac(if (salt.isEmpty()) ByteArray(32) else salt, secret)

    fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 0..(255 * 32)) { "Comprimento HKDF inválido" }
        val result = ByteArray(length)
        var previous = byteArrayOf()
        var offset = 0
        var counter = 1
        while (offset < length) {
            previous = hmac(prk, previous, info, byteArrayOf(counter.toByte()))
            val count = minOf(previous.size, length - offset)
            previous.copyInto(result, offset, 0, count)
            offset += count
            counter++
        }
        return result
    }

}
