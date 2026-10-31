package ssc.crypto

import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.math.BigInteger
import javax.crypto.interfaces.DHPublicKey
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement

class DiffieHellmanSession(private val groupName: String = "ffdhe2048") { // é sempre criada uma instância por participante e sessão

    private var privateKey: PrivateKey? = null
    var publicKey: PublicKey? = null
        private set

    fun createSession() {
        check(privateKey == null) { "Cria uma nova instância para uma nova sessão DH" }
        val keyPairGenerator = KeyPairGenerator.getInstance("DH").apply { initialize(DhGroup.parameters(groupName)) }
        val keyPair = keyPairGenerator.generateKeyPair() // gera o par de chaves DH

        publicKey = keyPair.public
        privateKey = keyPair.private
    }

    fun exportPublicKeyBytes(): ByteArray? = publicKey?.encoded // exporta a chave pública como bytes

    fun calculateSecret(pubKeyOther: ByteArray): ByteArray {

        val localPrivateKey = checkNotNull(privateKey) { // é necessário chamar createSession() antes de começar
            "É necessário criar a sessão antes de calcular o segredo"
        }

        // Reconstrói a chave pública a partir dos bytes exportados por PublicKey.encoded.
        require(pubKeyOther.size <= 1024) { "Codificação da chave pública DH demasiado grande" }
        val specification = X509EncodedKeySpec(pubKeyOther) // vamos receber a chave publica em bytes e portanto precisamos de a reconstruir
        val remotePublicKey = KeyFactory.getInstance("DH").generatePublic(specification) as DHPublicKey
        val expected = DhGroup.parameters(groupName)
        require(remotePublicKey.params.p == expected.p && remotePublicKey.params.g == expected.g) {
            "A chave remota não pertence ao grupo DH configurado"
        }
        val y = remotePublicKey.y
        require(y >= BigInteger.TWO && y <= expected.p - BigInteger.TWO) { "Valor público DH inválido" }
        val q = (expected.p - BigInteger.ONE) / BigInteger.TWO
        require(y.modPow(q, expected.p) == BigInteger.ONE) { "Chave DH fora do subgrupo esperado" }

        val agreement = KeyAgreement.getInstance("DH")
        agreement.init(localPrivateKey)
        agreement.doPhase(remotePublicKey, true)

        return agreement.generateSecret() // gera a chave secreta e retorna-a num buffer.
    }
}
