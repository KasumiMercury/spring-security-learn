package net.mercuryksm.spring_security_learn.config

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.io.Resource
import org.springframework.core.io.ResourceLoader
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import java.io.FileInputStream
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*

@Configuration
class JwtConfig(private val resourceLoader: ResourceLoader) {

    @Value("\${application.auth.jwt.private-key:#{null}}")
    private val privateKeyString: String? = null

    @Value("\${application.auth.jwt.public-key:#{null}}")
    private val publicKeyString: String? = null

    @Value("\${application.auth.jwt.private-key-path:#{null}}")
    private val privateKeyPath: String? = null

    @Value("\${application.auth.jwt.public-key-path:#{null}}")
    private val publicKeyPath: String? = null

    private var cachedRsaKey: RSAKey? = null

    @Bean
    fun jwtEncoder(): JwtEncoder {
        val jwk = getRsaKey()
        val jwks: JWKSource<SecurityContext> = ImmutableJWKSet(JWKSet(jwk))
        return NimbusJwtEncoder(jwks)
    }

    @Bean
    fun jwtDecoder(): JwtDecoder {
        return NimbusJwtDecoder.withPublicKey(getRsaKey().toRSAPublicKey()).build()
    }

    private fun getRsaKey(): RSAKey {
        if (cachedRsaKey != null) {
            return cachedRsaKey!!
        }

        cachedRsaKey = try {
            when {
                !privateKeyString.isNullOrBlank() && !publicKeyString.isNullOrBlank() -> {
                    loadRsaKeyFromStrings(privateKeyString, publicKeyString)
                }
                !privateKeyPath.isNullOrBlank() && !publicKeyPath.isNullOrBlank() -> {
                    loadRsaKeyFromFiles(privateKeyPath, publicKeyPath)
                }
                else -> {
                    generateRsaKey()
                }
            }
        } catch (e: Exception) {
            println("Warning: Failed to load configured JWT keys, generating new ones: ${e.message}")
            generateRsaKey()
        }

        return cachedRsaKey!!
    }

    private fun loadRsaKeyFromStrings(privateKeyStr: String, publicKeyStr: String): RSAKey {
        val privateKey = parsePrivateKey(privateKeyStr)
        val publicKey = parsePublicKey(publicKeyStr)
        
        return RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build()
    }

    private fun loadRsaKeyFromFiles(privateKeyPath: String, publicKeyPath: String): RSAKey {
        val privateKeyResource: Resource = resourceLoader.getResource(privateKeyPath)
        val publicKeyResource: Resource = resourceLoader.getResource(publicKeyPath)

        val privateKeyContent = privateKeyResource.inputStream.use { it.readBytes() }
        val publicKeyContent = publicKeyResource.inputStream.use { it.readBytes() }

        val privateKey = parsePrivateKey(String(privateKeyContent))
        val publicKey = parsePublicKey(String(publicKeyContent))

        return RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build()
    }

    private fun parsePrivateKey(keyContent: String): RSAPrivateKey {
        val cleanKey = keyContent
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace("-----BEGIN RSA PRIVATE KEY-----", "")
            .replace("-----END RSA PRIVATE KEY-----", "")
            .replace("\n", "")
            .replace("\r", "")
            .trim()

        val keyBytes = Base64.getDecoder().decode(cleanKey)
        val keySpec = PKCS8EncodedKeySpec(keyBytes)
        val keyFactory = KeyFactory.getInstance("RSA")
        return keyFactory.generatePrivate(keySpec) as RSAPrivateKey
    }

    private fun parsePublicKey(keyContent: String): RSAPublicKey {
        val cleanKey = keyContent
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace("-----BEGIN RSA PUBLIC KEY-----", "")
            .replace("-----END RSA PUBLIC KEY-----", "")
            .replace("\n", "")
            .replace("\r", "")
            .trim()

        val keyBytes = Base64.getDecoder().decode(cleanKey)
        val keySpec = X509EncodedKeySpec(keyBytes)
        val keyFactory = KeyFactory.getInstance("RSA")
        return keyFactory.generatePublic(keySpec) as RSAPublicKey
    }

    private fun generateRsaKey(): RSAKey {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048)
        }.generateKeyPair()

        return RSAKey.Builder(keyPair.public as RSAPublicKey)
            .privateKey(keyPair.private as RSAPrivateKey)
            .keyID(UUID.randomUUID().toString())
            .build()
    }
}