package net.mercuryksm.spring_security_learn.controller

import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/test")
class TestController {

    @GetMapping("/public")
    fun publicEndpoint(): Map<String, String> {
        return mapOf(
            "message" to "This is a public endpoint",
            "timestamp" to System.currentTimeMillis().toString()
        )
    }

    @GetMapping("/protected")
    fun protectedEndpoint(authentication: Authentication): Map<String, Any> {
        val jwt = authentication.principal as Jwt
        
        return mapOf(
            "message" to "This is a protected endpoint",
            "user" to (jwt.subject ?: "unknown"),
            "scope" to (jwt.getClaimAsString("scope") ?: ""),
            "userId" to (jwt.getClaimAsString("userId") ?: ""),
            "issued" to (jwt.issuedAt?.toString() ?: ""),
            "expires" to (jwt.expiresAt?.toString() ?: ""),
            "timestamp" to System.currentTimeMillis().toString()
        )
    }

    @GetMapping("/user-info")
    fun userInfo(authentication: Authentication): Map<String, Any> {
        val jwt = authentication.principal as Jwt
        
        return mapOf(
            "username" to (jwt.subject ?: "unknown"),
            "claims" to jwt.claims,
            "headers" to jwt.headers,
            "authorities" to authentication.authorities.map { it.authority }
        )
    }
}