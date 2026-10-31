package ssc.config

import ssc.config.dto.HandshakeConfig
import ssc.crypto.DhGroup
import ssc.crypto.MessageProtection

object HandshakeConfigValidator {
    fun validate(config: ValidatedCryptoConfig): HandshakeConfig {
        val settings = requireNotNull(config.config.handshake) { "É necessária a secção Handshake no XML" }
        DhGroup.parameters(settings.dhGroup)
        require(settings.kdf == "HKDF-SHA256") { "KDF do handshake não suportada" }
        require(settings.authentication == "HMAC-SHA256") { "Autenticação do handshake não suportada" }
        val cipher = MessageProtection(config.suite, settings.tagSizeBits, config.macSuite, (config.config.macKeySizeBits ?: 0) / 8)
        cipher.checkAvailability(config.config.keySizeBits)
        require(settings.randomSizeBytes == 32) { "O desafio SRV exige 256 bits (32 bytes)" }
        require(settings.maxPayloadBytes in 2048..(1024 * 1024)) { "MaxPayloadBytes deve estar entre 2048 e 1048576" }
        require(settings.socketTimeoutMillis in 100..120000) { "SocketTimeoutMillis fora dos limites permitidos" }
        require(settings.maxStreamRecords in 1..(1L shl 32)) { "MaxStreamRecords deve estar entre 1 e 4294967296" }
        return settings
    }
}
