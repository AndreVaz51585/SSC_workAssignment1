package ssc.protocol.handshake

import ssc.config.HandshakeConfigValidator
import ssc.config.ValidatedCryptoConfig
import ssc.crypto.DiffieHellmanSession
import ssc.crypto.MessageProtection
import ssc.crypto.HandshakeCrypto
import ssc.crypto.HandshakeKeySchedule
import ssc.crypto.ProtectionKeys
import ssc.protocol.HandshakePayloadCodec
import ssc.protocol.ProtocolMessageCodec
import ssc.protocol.dto.MessageType
import ssc.protocol.dto.ClientHelloPayload
import ssc.protocol.dto.ClientFinishedPayload
import ssc.protocol.dto.ProtocolMessage
import ssc.protocol.dto.ServerHelloPayload
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.security.SecureRandom


// class responsavél por realizar o ServerHandShake e recebe como argumento a configuração estabelecida e validada (lógica) do respetivo ficheiro de configuração
class ServerHandshake(private val config: ValidatedCryptoConfig) {
    private val settings = HandshakeConfigValidator.validate(config)
    private val keyBytes = config.config.keySizeBits / 8
    private val cipher = MessageProtection(config.suite, settings.tagSizeBits, config.macSuite, (config.config.macKeySizeBits ?: 0) / 8)

    fun perform(input: InputStream, output: OutputStream): HandshakeSession {
        try {

            val psk = HandshakeKeySchedule.authenticationSecret(requireNotNull(config.config.symmetricKey).copyBytes(), config.config.macKey?.copyBytes()) // pre-shared Secret

            val (first, hello) = receiveClientHello(input, psk)

            val random = SecureRandom()

            val serverRandom = ByteArray(settings.randomSizeBytes).also { random.nextBytes(it) }
            val srv = ByteArray(settings.randomSizeBytes).also { random.nextBytes(it) }
            val dh = DiffieHellmanSession(settings.dhGroup).apply { createSession() }
            val dhSecret = dh.calculateSecret(hello.dhPublicKey)
            // resumo dos bytes exatos a que estamos a responder
            val firstHash = HandshakeCrypto.sha256(HandshakeWire.bytes(first))

            // calcula uma chave e iv para proteger o type2
            // PSK + clientRandom + serverRandom + FirstHash -> bootstrap.key and bootstrap.iv
            // não utilizamos já o Z gerado pelo DH, isto porque o proxy ainda não tem acesso ao mesmo.
            val bootstrap = HandshakeKeySchedule.serverHelloProtection(psk, hello.clientRandom, serverRandom, firstHash, keyBytes, cipher.ivBytes, cipher.macKeyBytes)

            // TYPE 2 plaintext follows SEQY || SRV || CCC, with the public DH key as an extension.
            val serverHello = ServerHelloPayload(srv, hello.sequence + 1, hello.proposedConfig,
                requireNotNull(dh.exportPublicKeyBytes()))

            val secondFrame = sendServerHello(output, serverHello, serverRandom, bootstrap, firstHash)

            // agora o resumo abrange o hash das duas mensgens enviadas na ordem em que foram trocadas.
            val helloHash = HandshakeCrypto.sha256(HandshakeWire.bytes(first), HandshakeWire.bytes(secondFrame))

            // esta derivação combina o DH secret com a PSK e o contexto deste handshake.
            val sessionSecret = HandshakeKeySchedule.sessionSecret(psk, dhSecret, hello.clientRandom, srv, helloHash)
            dhSecret.fill(0)

            // ou seja no fundo temos 3 Chaves
            // dh secret, resultado chave secreta efemera.
            // 2. bootstrap.key e iv, chave e IV utilizados para encriptar a mensagem Type2, junta
            // 3. session secret, segredo intermédio do qual derivamos a proteção de type3 e depois as chaves de trafégo.


            val (third, finished) = receiveClientFinished(input, sessionSecret, helloHash, hello.sequence, srv)

            val fullHash = HandshakeCrypto.sha256(HandshakeWire.bytes(first), HandshakeWire.bytes(secondFrame), HandshakeWire.bytes(third))
            val keys = HandshakeKeySchedule.trafficKeys(sessionSecret, fullHash, keyBytes, cipher.ivBytes, cipher.macKeyBytes)
            sessionSecret.fill(0)
            psk.fill(0)
            return HandshakeSession(keys, finished.media, hello.sequence + 3, fullHash, finished.rangeHeader, config.suite, config.macSuite)
        } catch (exception: Exception) {
            HandshakeWire.alert(output)
            throw exception
        }
    }

    private fun receiveClientHello(input: InputStream, psk: ByteArray): Pair<ProtocolMessage, ClientHelloPayload> {
        // realiza a leitura da primeira mensagem enviada pelo Proxy, o Client_hello, lê do buffer valida o tamanho tendo em conta o expectavél e transforma no dto.
        // corresponde ao envelope da mensagem.
        val first = HandshakeWire.read(input, MessageType.CLIENT_HELLO, settings.maxPayloadBytes)

        // realiza as validações do conteudo e bytes da primeira mensagem, no fundo interpreta os valores que constam no envelope
        val hello = HandshakePayloadCodec.decodeClientHello(first.payload, settings.randomSizeBytes)

        // separa os bytes sobre o qual vamos calcular a tag de verifiicação

        //payload recebido = body || tag
        // body = SEQX || configuração || clientRandom || pública DH
        val body = first.payload.copyOfRange(0, first.payload.size - hello.authenticationTag.size)


        // aqui o server está a calcular a mesma deriviação efetuada pelo proxy para ober a chave utilziada no calculo do hmac
        // o client random pode ser publico, e a authKey usada no HMAC é calculada tendo em conta a psk e o clientrandom, para o servidor saber exatmaente qual a chave utilziada
        // mesmo sabendo o clientrandom, sem psk não é possivel reproduzir a chave.
        val authKey = HandshakeKeySchedule.clientHelloAuthentication(psk, hello.clientRandom)

        // tag = HMAC(authKey, header||body)
        val expectedTag = HandshakeCrypto.hmac(authKey, ProtocolMessageCodec.encodeHeader(first.header), body)
        // Constant-time comparison for authentication material. Verify before expensive DH work.
        require(MessageDigest.isEqual(expectedTag, hello.authenticationTag)) { "Autenticação do ClientHello falhou" }
        require(hello.proposedConfig == HandshakeWire.proposal(config, settings)) { "PCC não permitida pela configuração local" }
        require(hello.sequence in 0 until Int.MAX_VALUE.toLong()) { "Sequência inicial inválida" }
        return first to hello
    }

    private fun sendServerHello(output: OutputStream, serverHello: ServerHelloPayload,
                                serverRandom: ByteArray, bootstrap: ProtectionKeys, firstHash: ByteArray): ProtocolMessage {
        val plaintext = HandshakePayloadCodec.encodeServerHello(serverHello) // construimos os campos em plain_text e codificamos-los

        val second = HandshakeWire.frame(MessageType.SERVER_HELLO,
            ByteArray(serverRandom.size + plaintext.size + settings.tagSizeBits / 8))

        // aqui é onde acontece a proteção autenticada selecionada no XML, sendo o plaintext o conteudo a cifrar, a key e o iv derivados e os AAD, resultado é cipherText com a tag de autenticação acrescentada.
        val encrypted = cipher.encrypt(plaintext, bootstrap.key.copyBytes(), bootstrap.iv.copyBytes(),
            ProtocolMessageCodec.encodeHeader(second.header) + serverRandom + firstHash, bootstrap.macKey?.copyBytes())

        val secondFrame = second.copy(payload = serverRandom + encrypted)
        // envia o segundo frame.
        HandshakeWire.send(output, secondFrame, settings.maxPayloadBytes)
        return secondFrame
    }

    private fun receiveClientFinished(input: InputStream, sessionSecret: ByteArray, helloHash: ByteArray,
                                      clientSequence: Long, srv: ByteArray): Pair<ProtocolMessage, ClientFinishedPayload> {
        // TYPE 3 is expected next: no stream may start before these checks pass.
        // espera pela mensagem
        val third = HandshakeWire.read(input, MessageType.CLIENT_FINISHED, settings.maxPayloadBytes)
        // deriva a chave/iv próprios a partir de sessionSecret e helloHash
        val protection = HandshakeKeySchedule.clientFinishedProtection(sessionSecret, helloHash, keyBytes, cipher.ivBytes, cipher.macKeyBytes)
        val finishedBytes = cipher.decrypt(third.payload, protection.key.copyBytes(), protection.iv.copyBytes(),
            ProtocolMessageCodec.encodeHeader(third.header) + helloHash, protection.macKey?.copyBytes())
        val finished = HandshakePayloadCodec.decodeClientFinished(finishedBytes)
        require(finished.sequence == clientSequence + 2) { "Sequência do ClientFinished inválida" }
        require(MessageDigest.isEqual(finished.challengeResponse, HandshakeCrypto.sha256(srv))) { "Resposta ao desafio inválida" }
        HandshakeWire.validateMedia(finished.media)
        HandshakeWire.validateRange(finished.rangeHeader)
        return third to finished
    }
}
