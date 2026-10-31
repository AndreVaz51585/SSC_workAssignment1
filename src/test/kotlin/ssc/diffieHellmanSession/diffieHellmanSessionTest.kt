package ssc.diffieHellmanSession

import ssc.crypto.DiffieHellmanSession
import java.security.spec.InvalidKeySpecException
import java.security.KeyFactory
import java.math.BigInteger
import javax.crypto.spec.DHPublicKeySpec
import ssc.crypto.DhGroup
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull

class diffieHellmanSessionTest {

    @Test
    fun `test both participants calculate the same secret from encoded public keys`() {
        val proxy = DiffieHellmanSession().apply { createSession() }
        val server = DiffieHellmanSession().apply { createSession() }
        val proxyPublicKey = assertNotNull(proxy.exportPublicKeyBytes())
        val serverPublicKey = assertNotNull(server.exportPublicKeyBytes())

        val proxySecret = proxy.calculateSecret(serverPublicKey)
        val serverSecret = server.calculateSecret(proxyPublicKey)

        assertContentEquals(proxySecret, serverSecret)
    }

    @Test
    fun `test invalid public key encoding is rejected`() {
        val session = DiffieHellmanSession().apply { createSession() }

        assertFailsWith<InvalidKeySpecException> {
            session.calculateSecret(byteArrayOf(1, 2, 3))
        }
    }

    @Test
    fun `test secret calculation requires an initialized session`() {
        val session = DiffieHellmanSession()

        assertFailsWith<IllegalStateException> {
            session.calculateSecret(byteArrayOf())
        }
    }

    @Test
    fun `test configured dh group has expected public parameters`() {
        val group = DhGroup.parameters("ffdhe2048")
        assertEquals(2048, group.p.bitLength())
        assertEquals(BigInteger.TWO, group.g)
    }

    @Test
    fun `test remote public key must belong to configured group`() {
        val group = DhGroup.parameters("ffdhe2048")
        val key = KeyFactory.getInstance("DH").generatePublic(
            DHPublicKeySpec(BigInteger.TWO, group.p - BigInteger.TWO, group.g))
        val session = DiffieHellmanSession().apply { createSession() }
        assertFails { session.calculateSecret(key.encoded) }
    }

    @Test
    fun `test degenerate dh public value is rejected`() {
        val group = DhGroup.parameters("ffdhe2048")
        val session = DiffieHellmanSession().apply { createSession() }
        assertFails {
            val key = KeyFactory.getInstance("DH").generatePublic(DHPublicKeySpec(BigInteger.ONE, group.p, group.g))
            session.calculateSecret(key.encoded)
        }
    }
}
