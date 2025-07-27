package net.mercuryksm.spring_security_learn.controller

import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.JwtEncoderParameters
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.time.Instant

@RestController
@RequestMapping("/api/auth")
class AuthController(private val jwtEncoder: JwtEncoder) {

    @PostMapping("/token")
    fun generateToken(@RequestBody loginRequest: LoginRequest): TokenResponse {
        // ダミーの認証 - 実際の実装では、ユーザー認証を行う
        if (loginRequest.username.isBlank() || loginRequest.password.isBlank()) {
            throw IllegalArgumentException("Username and password are required")
        }

        val now = Instant.now()
        val expiry = now.plusSeconds(3600) // 1時間の有効期限

        val claims = JwtClaimsSet.builder()
            .issuer("spring-security-learn")
            .issuedAt(now)
            .expiresAt(expiry)
            .subject(loginRequest.username)
            .claim("scope", "read write")
            .claim("userId", generateUserId(loginRequest.username))
            .build()

        val jwt = jwtEncoder.encode(JwtEncoderParameters.from(claims))

        return TokenResponse(
            token = jwt.tokenValue,
            type = "Bearer",
            expiresIn = 3600
        )
    }

    private fun generateUserId(username: String): Long {
        // ダミーのユーザーID生成
        return username.hashCode().toLong().coerceAtLeast(1L)
    }

    data class LoginRequest(
        val username: String,
        val password: String
    )

    data class TokenResponse(
        val token: String,
        val type: String,
        val expiresIn: Long
    )
}