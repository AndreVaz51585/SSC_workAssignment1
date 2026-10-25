package ssc.config

import org.w3c.dom.Document
import org.w3c.dom.Element
import org.xml.sax.ErrorHandler
import org.xml.sax.SAXParseException
import ssc.config.dto.CryptoConfig
import ssc.config.dto.KeyMaterial
import java.nio.file.Files
import java.util.Base64
import java.util.HexFormat
import java.io.File
import javax.xml.XMLConstants
import javax.xml.parsers.DocumentBuilderFactory

object CryptoConfigLoader {

    fun load(path: String): CryptoConfig {
        val document = parseXml(path)
        document.documentElement.normalize()

        val root = document.documentElement // ProxyCryptoConfig ou ServerCryptoConfig

        require(root.tagName in setOf("ProxyCryptoConfig", "ServerCryptoConfig")) {
            "A raiz deve ser ProxyCryptoConfig ou ServerCryptoConfig"
        }
        require(root.getAttribute("version") == "1.0") {
            "A versão do XML deve ser 1.0"
        }

        requireChildren(root, "SymCipherSuite", "MACSuite", "ConfiguredKeys")
        val suite = getElement(root, "SymCipherSuite")
        requireChildren(suite, "Algorithm", "Mode", "InitializationVector", "Padding")
        val initializationVector = getElement(suite, "InitializationVector")
        requireChildren(initializationVector, "IV", "IVSize")
        val macSuite = getElement(root, "MACSuite")
        requireChildren(macSuite, "Algorithm")
        val keys = getElement(root, "ConfiguredKeys")
        requireChildren(keys, "SymmetricKey", "MACKey")
        val symmetricKey = getElement(keys, "SymmetricKey")
        requireChildren(symmetricKey, "SKey", "Keysize")
        val macKey = getElement(keys, "MACKey")
        requireChildren(macKey, "MacKey", "MacKeySize")
        require(getElement(initializationVector, "IVSize").getAttribute("unit") == "bits") {
            "IVSize deve indicar unit=bits"
        }

        return CryptoConfig(
            algorithm = getElementValue(suite, "Algorithm"),
            mode = getElementValue(suite, "Mode"),
            iv = getNullableElementValue(initializationVector, "IV"),
            ivSizeBits = getNullableInteger(initializationVector, "IVSize"),
            padding = getNullableElementValue(suite, "Padding"),
            macAlgorithm = getNullableElementValue(macSuite, "Algorithm"),
            symmetricKey = getKey(symmetricKey, "SKey"),
            keySizeBits = getNullableInteger(symmetricKey, "Keysize")
                ?: throw IllegalArgumentException("Keysize não pode ser NULL"),
            macKey = getKey(macKey, "MacKey"),
            macKeySizeBits = getNullableInteger(macKey, "MacKeySize"),
        )
    }

    // Interpreta o ficheiro XML sem permitir DTDs nem referências a recursos externos.
    private fun parseXml(path: String): Document {
        val factory = DocumentBuilderFactory.newInstance().apply {
            setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
            setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
            setFeature("http://xml.org/sax/features/external-general-entities", false)
            setFeature("http://xml.org/sax/features/external-parameter-entities", false)
            setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")
            setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "")
            isXIncludeAware = false
            isExpandEntityReferences = false
        }
        val builder = factory.newDocumentBuilder()
        // Evita que erros de parsing imprimam excertos do XML que possam conter segredos.
        builder.setErrorHandler(object : ErrorHandler {
            override fun warning(exception: SAXParseException) = Unit
            override fun error(exception: SAXParseException): Nothing = throw exception
            override fun fatalError(exception: SAXParseException): Nothing = throw exception
        })
        return try {
            Files.newInputStream(File(path).toPath()).use { input ->
                val bytes = input.readNBytes(64 * 1024 + 1)
                require(bytes.size <= 64 * 1024) { "XML excede o limite de 64 KiB" }
                builder.parse(bytes.inputStream())
            }
        } catch (_: org.xml.sax.SAXException) {
            throw IllegalArgumentException("XML inválido: verifica a sintaxe; DTDs e entidades externas não são permitidas")
        }
    }

    // Procura apenas nos filhos diretos, para não confundir tags de secções diferentes.
    private fun getElement(parent: Element, tag: String): Element {
        val children = parent.childNodes
        val matches = (0 until children.length)
            .map { children.item(it) }
            .filterIsInstance<Element>()
            .filter { it.tagName == tag }

        require(matches.size == 1) {
            "Deve existir exatamente um <$tag> dentro de <${parent.tagName}>"
        }
        return matches.single()
    }

    private fun getElementValue(parent: Element, tag: String): String {
        val element = getElement(parent, tag)
        val attributes = when (tag) {
            "SKey", "MacKey" -> arrayOf("encoding")
            "IVSize" -> arrayOf("unit")
            else -> emptyArray()
        }
        requireAttributes(element, *attributes)
        require((0 until element.childNodes.length).none { element.childNodes.item(it) is Element }) {
            "<$tag> deve conter apenas texto, sem elementos internos"
        }
        val value = element.textContent.trim()
        require(value.isNotEmpty()) {
            "<$tag> não pode estar vazio; usa NULL quando aplicável"
        }
        return value
    }

    // Reject typos and duplicate sections instead of silently using part of a configuration.
    private fun requireChildren(parent: Element, vararg names: String) {
        val attributes = if (parent.parentNode is Document) arrayOf("version") else emptyArray()
        requireAttributes(parent, *attributes)
        require((0 until parent.childNodes.length).none {
            val node = parent.childNodes.item(it)
            (node.nodeType == org.w3c.dom.Node.TEXT_NODE || node.nodeType == org.w3c.dom.Node.CDATA_SECTION_NODE) &&
                node.textContent.isNotBlank()
        }) { "Texto inesperado dentro de <${parent.tagName}>" }
        val elements = (0 until parent.childNodes.length)
            .map { parent.childNodes.item(it) }.filterIsInstance<Element>()
        require(elements.all { it.tagName in names }) { "Elemento inesperado dentro de <${parent.tagName}>" }
        names.forEach { getElement(parent, it) }
    }

    private fun requireAttributes(element: Element, vararg allowed: String) {
        require((0 until element.attributes.length).all { element.attributes.item(it).nodeName in allowed }) {
            "Atributo inesperado em <${element.tagName}>"
        }
    }

    private fun getNullableInteger(parent: Element, tag: String): Int? =
        getNullableElementValue(parent, tag)?.let {
            it.toIntOrNull() ?: throw IllegalArgumentException("<$tag> deve ser um número inteiro ou NULL")
        }

    private fun getKey(parent: Element, tag: String): KeyMaterial? {
        val element = getElement(parent, tag)
        val value = getNullableElementValue(parent, tag) ?: return null
        // Hex is the documented default when the example omits the encoding attribute.
        val encoding = element.getAttribute("encoding").ifEmpty { "hex" }
        val bytes = try {
            when (encoding.lowercase()) {
                "hex" -> HexFormat.of().parseHex(value)
                "base64" -> Base64.getDecoder().decode(value)
                else -> throw IllegalArgumentException()
            }
        } catch (_: IllegalArgumentException) {
            // Never expose the original parser exception: it can contain key material.
            throw IllegalArgumentException("<$tag> deve conter material válido em hex ou base64")
        }
        return KeyMaterial(bytes)
    }

    private fun getNullableElementValue(parent: Element, tag: String): String? =
        getElementValue(parent, tag).takeUnless { it == "NULL" }
}
