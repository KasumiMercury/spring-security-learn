package net.mercuryksm.spring_security_learn.config

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.bind.ConstructorBinding
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

@ConfigurationProperties("application.auth.jwt", ignoreUnknownFields = true, ignoreInvalidFields = true)
data class JwtProperties @ConstructorBinding constructor(
    /**
     * 公開鍵。直接キー文字列を指定するか、"file:path/to/public.pem"形式でファイルパスを指定可能
     */
    val publicKey: String? = null,
    /**
     * 秘密鍵。直接キー文字列を指定するか、"file:path/to/private.pem"形式でファイルパスを指定可能  
     */
    val privateKey: String? = null
)

data class JwtKeys(
    val publicKey: RSAPublicKey,
    val privateKey: RSAPrivateKey
)