package net.mercuryksm.spring_security_learn.config

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.io.Resource
import org.springframework.core.io.ResourceLoader
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*

@Configuration
@EnableConfigurationProperties(JwtProperties::class)
class JwtConfig(
    private val jwtProperties: JwtProperties,
    private val resourceLoader: ResourceLoader
) {

    private var cachedJwtKeys: JwtKeys? = null

    @Bean
    fun jwtEncoder(): JwtEncoder {
        val jwtKeys = getJwtKeys()
        val rsaKey = RSAKey.Builder(jwtKeys.publicKey)
            .privateKey(jwtKeys.privateKey)
            .keyID(UUID.randomUUID().toString())
            .build()
        
        val jwks: JWKSource<SecurityContext> = ImmutableJWKSet(JWKSet(rsaKey))
        return NimbusJwtEncoder(jwks)
    }

    private fun getJwtKeys(): JwtKeys {
        if (cachedJwtKeys != null) {
            return cachedJwtKeys!!
        }

        cachedJwtKeys = try {
            when {
                !jwtProperties.privateKey.isNullOrBlank() && !jwtProperties.publicKey.isNullOrBlank() -> {
                    loadKeys(jwtProperties.privateKey, jwtProperties.publicKey)
                }
                else -> {
                    generateKeys()
                }
            }
        } catch (e: Exception) {
            println("Warning: Failed to load configured JWT keys, generating new ones: ${e.message}")
            generateKeys()
        }

        return cachedJwtKeys!!
    }

    private fun loadKeys(privateKeyValue: String, publicKeyValue: String): JwtKeys {
        val privateKey = loadKey(privateKeyValue, ::parsePrivateKey)
        val publicKey = loadKey(publicKeyValue, ::parsePublicKey)
        return JwtKeys(publicKey, privateKey)
    }

    private fun <T> loadKey(keyValue: String, keyParser: (String) -> T): T {
        return if (keyValue.startsWith("file:")) {
            // ファイルパスから読み込み
            val filePath = keyValue.removePrefix("file:")
            val resource: Resource = resourceLoader.getResource(filePath)
            val keyContent = resource.inputStream.use { String(it.readBytes()) }
            keyParser(keyContent)
        } else {
            // 直接キー文字列として解析
            keyParser(keyValue)
        }
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

    private fun generateKeys(): JwtKeys {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048)
        }.generateKeyPair()

        return JwtKeys(
            publicKey = keyPair.public as RSAPublicKey,
            privateKey = keyPair.private as RSAPrivateKey
        )
    }
}