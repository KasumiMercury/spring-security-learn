package net.mercuryksm.spring_security_learn.config

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*

@Configuration
@EnableConfigurationProperties(JwtProperties::class)
class JwtConfig(private val jwtProperties: JwtProperties) {

    @Bean
    fun jwtEncoder(): JwtEncoder {
        val (publicKey, privateKey) = getOrGenerateKeys()
        
        val rsaKey = RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build()
        
        val jwks: JWKSource<SecurityContext> = ImmutableJWKSet(JWKSet(rsaKey))
        return NimbusJwtEncoder(jwks)
    }

    private fun getOrGenerateKeys(): Pair<RSAPublicKey, RSAPrivateKey> {
        return if (jwtProperties.privateKey != null && jwtProperties.publicKey != null) {
            // Spring Bootが自動変換したキーを使用
            Pair(jwtProperties.publicKey, jwtProperties.privateKey)
        } else {
            // キーが設定されていない場合は生成
            println("No JWT keys configured, generating new RSA key pair")
            generateKeyPair()
        }
    }

    private fun generateKeyPair(): Pair<RSAPublicKey, RSAPrivateKey> {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048)
        }.generateKeyPair()

        return Pair(
            keyPair.public as RSAPublicKey,
            keyPair.private as RSAPrivateKey
        )
    }
}