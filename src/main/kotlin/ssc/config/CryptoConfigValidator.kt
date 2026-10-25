package ssc.config

import ssc.config.dto.CryptoConfig
import java.security.GeneralSecurityException
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac

object CryptoConfigValidator {
    fun validate(config: CryptoConfig): ValidatedCryptoConfig {
        val suite = CipherSuite.resolve(config.algorithm, config.mode)
        require(config.padding == null || config.padding.equals("NoPadding", true)) {
            "As suites planeadas exigem Padding=NULL ou NoPadding"
        }
        // Project policy: the XML describes nonce length; it cannot supply a reusable fixed nonce.
        require(config.iv == null) {
            "IV deve ser NULL: o protocolo irá gerar/derivar valores por sessão e mensagem"
        }
        require(config.ivSizeBits == suite.ivSizeBits) {
            "A política de ${suite.algorithm}/${suite.mode} exige IVSize=${suite.ivSizeBits} bits"
        }
        require(config.keySizeBits in suite.keySizesBits) {
            "Keysize incompatível com a suite; tamanhos permitidos: ${suite.keySizesBits}"
        }
        val symmetricKey = requireNotNull(config.symmetricKey) {
            "SKey é obrigatório como segredo inicial de autenticação (bootstrap PSK)"
        }
        require(symmetricKey.sizeBits == config.keySizeBits) {
            "O tamanho descodificado de SKey não corresponde a Keysize"
        }

        val mac = when (suite.protection) {
            ProtectionCategory.AEAD -> {
                require(config.macAlgorithm == null && config.macKey == null && config.macKeySizeBits == null) {
                    "A política AEAD exige MACSuite/Algorithm, MacKey e MacKeySize iguais a NULL; a tag é integrada"
                }
                null
            }
            ProtectionCategory.ENCRYPT_THEN_MAC -> {
                val selected = MacSuite.resolve(requireNotNull(config.macAlgorithm) {
                    "AES/CTR exige um HMAC separado; CTR isolado não fornece autenticidade"
                })
                val key = requireNotNull(config.macKey) { "MacKey é obrigatório para Encrypt-then-MAC" }
                val size = requireNotNull(config.macKeySizeBits) { "MacKeySize é obrigatório para Encrypt-then-MAC" }
                require(size >= selected.minimumKeySizeBits && size % 8 == 0) {
                    "Política HMAC: MacKeySize deve ser múltiplo de 8 e ter pelo menos ${selected.minimumKeySizeBits} bits"
                }
                require(key.sizeBits == size) { "O tamanho descodificado de MacKey não corresponde a MacKeySize" }
                require(!MessageDigest.isEqual(symmetricKey.copyBytes(), key.copyBytes())) {
                    "SKey e MacKey devem ser segredos independentes"
                }
                selected
            }
        }
        checkJdkSupport(suite, config.keySizeBits, mac)
        return ValidatedCryptoConfig(config, suite, mac)
    }

    private fun checkJdkSupport(suite: CipherSuite, keySizeBits: Int, mac: MacSuite?) {
        try {
            Cipher.getInstance(suite.transformation)
            require(Cipher.getMaxAllowedKeyLength(suite.transformation) >= keySizeBits) {
                "A política do JDK não permite o tamanho de chave configurado"
            }
            if (mac != null) Mac.getInstance(mac.jcaName)
        } catch (_: GeneralSecurityException) {
            throw IllegalArgumentException("A suite configurada não está disponível nos providers deste JDK")
        }
    }
}
