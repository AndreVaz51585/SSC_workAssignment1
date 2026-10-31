package ssc.crypto

import ssc.config.CipherSuite
import ssc.config.ProtectionCategory
import java.security.GeneralSecurityException
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Central suite adapter. Protocol coordinators do not need to know JCA parameter types. */
class AeadCipher(val suite: CipherSuite, private val tagBits: Int) {
    init {
        require(suite.protection == ProtectionCategory.AEAD) {
            "${suite.algorithm}/${suite.mode} ainda não está integrada na camada AEAD"
        }
        require(tagBits in suite.tagSizesBits) { "TagSizeBits incompatível com a suite selecionada" }
    }

    val tagBytes: Int get() = tagBits / 8
    val ivBytes: Int get() = suite.ivSizeBits / 8

    /** Check the actual provider + key/parameter combination before opening application sockets. */
    fun checkAvailability(keySizeBits: Int) {
        require(keySizeBits in suite.keySizesBits) { "Tamanho de chave incompatível com a suite" }
        try {
            val cipher = Cipher.getInstance(suite.transformation)
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(ByteArray(keySizeBits / 8), suite.algorithm),
                parameters(ByteArray(ivBytes)))
        } catch (_: GeneralSecurityException) {
            throw IllegalArgumentException("O provider do JDK não suporta os parâmetros da suite selecionada")
        }
    }

    fun encrypt(plaintext: ByteArray, key: ByteArray, nonce: ByteArray, aad: ByteArray): ByteArray =
        apply(Cipher.ENCRYPT_MODE, plaintext, key, nonce, aad)

    fun decrypt(ciphertext: ByteArray, key: ByteArray, nonce: ByteArray, aad: ByteArray): ByteArray {
        require(ciphertext.size >= tagBytes) { "Ciphertext sem tag completa" }
        return apply(Cipher.DECRYPT_MODE, ciphertext, key, nonce, aad)
    }

    private fun apply(mode: Int, input: ByteArray, key: ByteArray, nonce: ByteArray, aad: ByteArray): ByteArray {
        require(key.size * 8 in suite.keySizesBits) { "Tamanho da chave derivada incompatível com a suite" }
        require(nonce.size == ivBytes) { "Comprimento do nonce incompatível com a suite" }
        // New Cipher per operation: no provider state or nonce history is shared between records/threads.
        val cipher = Cipher.getInstance(suite.transformation)
        cipher.init(mode, SecretKeySpec(key, suite.algorithm), parameters(nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(input) // Appends the AEAD tag / verifies it before returning plaintext.
    }

    private fun parameters(nonce: ByteArray): AlgorithmParameterSpec = when (suite) {
        CipherSuite.AES_GCM -> GCMParameterSpec(tagBits, nonce)
        CipherSuite.CHACHA20_POLY1305 -> IvParameterSpec(nonce) // Poly1305 has a fixed 128-bit tag.
        CipherSuite.AES_CTR_HMAC -> throw IllegalArgumentException("CTR exige Encrypt-then-MAC, não AEAD")
    }
}
