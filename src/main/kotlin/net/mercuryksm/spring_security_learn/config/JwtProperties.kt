package net.mercuryksm.spring_security_learn.config

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.bind.ConstructorBinding
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

@ConfigurationProperties("application.auth.jwt", ignoreUnknownFields = true, ignoreInvalidFields = true)
data class JwtProperties @ConstructorBinding constructor(
    /**
     * 公開鍵。PEM文字列、file:パス、classpath:パスをサポート
     * Spring Bootが自動的にRSAPublicKeyに変換
     */
    val publicKey: RSAPublicKey? = null,
    /**
     * 秘密鍵。PEM文字列、file:パス、classpath:パスをサポート
     * Spring Bootが自動的にRSAPrivateKeyに変換
     */
    val privateKey: RSAPrivateKey? = null
)