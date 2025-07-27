package net.mercuryksm.spring_security_learn.config

import org.springframework.boot.context.properties.ConfigurationPropertiesBinding
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.convert.converter.Converter
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*

@Configuration
class RsaKeyConverterConfig {

    @Bean
    @ConfigurationPropertiesBinding
    fun rsaPrivateKeyConverter(): Converter<String, RSAPrivateKey> {
        return Converter { source ->
            try {
                // file:やclasspath:プレフィックスの処理は省略（Spring Bootが処理）
                val cleanKey = source
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
                keyFactory.generatePrivate(keySpec) as RSAPrivateKey
            } catch (e: Exception) {
                throw IllegalArgumentException("Invalid RSA private key format", e)
            }
        }
    }

    @Bean
    @ConfigurationPropertiesBinding
    fun rsaPublicKeyConverter(): Converter<String, RSAPublicKey> {
        return Converter { source ->
            try {
                val cleanKey = source
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
                keyFactory.generatePublic(keySpec) as RSAPublicKey
            } catch (e: Exception) {
                throw IllegalArgumentException("Invalid RSA public key format", e)
            }
        }
    }
}