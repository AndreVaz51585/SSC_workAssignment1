package ssc.crypto

import ssc.config.CipherSuite
import ssc.config.MacSuite
import ssc.config.NonceRequirement
import ssc.config.ProtectionCategory
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.security.MessageDigest
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Uniform authenticated protection API: built-in AEAD or explicit CTR Encrypt-then-MAC. */
class MessageProtection(
    val suite: CipherSuite,
    private val tagBits: Int,
    val macSuite: MacSuite? = null,
    val macKeyBytes: Int = 0,
) {
    private val aead: AeadCipher?
    val tagBytes get() = tagBits / 8
    val ivBytes get() = suite.ivSizeBits / 8

    init {
        when (suite.protection) {
            ProtectionCategory.AEAD -> {
                require(macSuite == null && macKeyBytes == 0) { "AEAD não usa MAC separado" }
                aead = AeadCipher(suite, tagBits)
            }
            ProtectionCategory.ENCRYPT_THEN_MAC -> {
                val mac = requireNotNull(macSuite) { "CTR exige um HMAC" }
                require(tagBits == mac.tagSizeBits) { "TagSizeBits deve corresponder ao HMAC completo selecionado" }
                require(macKeyBytes * 8 >= mac.minimumKeySizeBits && macKeyBytes <= 255 * 32) { "Comprimento da chave HMAC não suportado" }
                aead = null
            }
        }
    }

    fun checkAvailability(keySizeBits: Int) {
        aead?.let { it.checkAvailability(keySizeBits); return }
        require(keySizeBits in suite.keySizesBits)
        try {
            Cipher.getInstance(suite.transformation).init(Cipher.ENCRYPT_MODE,
                SecretKeySpec(ByteArray(keySizeBits / 8), suite.algorithm), IvParameterSpec(ByteArray(ivBytes)))
            val mac = requireNotNull(macSuite)
            Mac.getInstance(mac.jcaName).init(SecretKeySpec(ByteArray(macKeyBytes), mac.jcaName))
        } catch (_: GeneralSecurityException) {
            throw IllegalArgumentException("Provider não suporta os parâmetros CTR/HMAC selecionados")
        }
    }

    fun encrypt(plaintext: ByteArray, key: ByteArray, iv: ByteArray, aad: ByteArray, macKey: ByteArray? = null): ByteArray {
        aead?.let { return it.encrypt(plaintext, key, iv, aad) }
        validate(key, iv, macKey)
        val ciphertext = ctr(Cipher.ENCRYPT_MODE, plaintext, key, iv)
        return ciphertext + tag(requireNotNull(macKey), iv, aad, ciphertext)
    }

    fun decrypt(encrypted: ByteArray, key: ByteArray, iv: ByteArray, aad: ByteArray, macKey: ByteArray? = null): ByteArray {
        aead?.let { return it.decrypt(encrypted, key, iv, aad) }
        validate(key, iv, macKey)
        require(encrypted.size >= tagBytes) { "Ciphertext sem HMAC completo" }
        val ciphertext = encrypted.copyOfRange(0, encrypted.size - tagBytes)
        val receivedTag = encrypted.copyOfRange(ciphertext.size, encrypted.size)
        val expectedTag = tag(requireNotNull(macKey), iv, aad, ciphertext)
        if (!MessageDigest.isEqual(expectedTag, receivedTag)) throw AEADBadTagException("Autenticação Encrypt-then-MAC falhou")
        // No cipher initialization/decryption or plaintext release occurs before MAC verification.
        return ctr(Cipher.DECRYPT_MODE, ciphertext, key, iv)
    }

    /** Disjoint CTR counter domains; AEAD retains base XOR zero-padded sequence. */
    fun nonce(base: ByteArray, sequence: Long): ByteArray {
        require(base.size == ivBytes && sequence >= 0)
        val encoded = ByteBuffer.allocate(8).putLong(sequence).array()
        return when (suite.nonceRequirement) {
            NonceRequirement.UNIQUE_PER_KEY -> base.copyOf().also { result ->
                for (i in encoded.indices) result[result.size - 8 + i] = (result[result.size - 8 + i].toInt() xor encoded[i].toInt()).toByte()
            }
            NonceRequirement.DISJOINT_COUNTER_RANGES_PER_KEY -> ByteArray(ivBytes).also { result ->
                // Initial counter = (derived 64-bit prefix XOR sequence) || 0^64.
                // A ByteArray record uses far fewer than 2^64 AES blocks, so no carry enters the prefix.
                for (i in encoded.indices) result[i] = (base[i].toInt() xor encoded[i].toInt()).toByte()
            }
        }
    }

    private fun validate(key: ByteArray, iv: ByteArray, macKey: ByteArray?) {
        require(key.size * 8 in suite.keySizesBits && iv.size == ivBytes) { "Chave/IV incompatíveis com CTR" }
        require(macKey != null && macKey.size == macKeyBytes) { "Chave HMAC derivada inválida" }
    }

    private fun ctr(mode: Int, bytes: ByteArray, key: ByteArray, iv: ByteArray): ByteArray =
        Cipher.getInstance(suite.transformation).run {
            init(mode, SecretKeySpec(key, suite.algorithm), IvParameterSpec(iv))
            doFinal(bytes)
        }

    private fun tag(key: ByteArray, iv: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray {
        val selected = requireNotNull(macSuite)
        return Mac.getInstance(selected.jcaName).run {
            init(SecretKeySpec(key, selected.jcaName))
            update("SSC-WA1/1:1/ETM\u0000".toByteArray(Charsets.US_ASCII))
            update(ByteBuffer.allocate(4).putInt(aad.size).array())
            update(aad)
            update(iv)
            doFinal(ciphertext)
        }
    }
}
