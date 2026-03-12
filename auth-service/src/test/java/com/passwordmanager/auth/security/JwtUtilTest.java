package com.passwordmanager.auth.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;

class JwtUtilTest {

    private JwtUtil jwtUtil;

    @BeforeEach
    void setUp() {
        jwtUtil = new JwtUtil();
        ReflectionTestUtils.setField(jwtUtil, "secret", "12345678901234567890123456789012");
        ReflectionTestUtils.setField(jwtUtil, "expiration", 60_000L);
    }

    @Test
    void generateAndValidateToken() {
        String token = jwtUtil.generateToken("alice", 42L, "USER");

        assertTrue(jwtUtil.validateToken(token));
        assertTrue(jwtUtil.validateToken(token, "alice"));
        assertEquals("alice", jwtUtil.extractUsername(token));
        assertEquals(42L, jwtUtil.extractUserId(token));
        assertEquals("USER", jwtUtil.extractRole(token));
    }

    @Test
    void invalidTokenFailsValidation() {
        assertFalse(jwtUtil.validateToken("bad.token.value"));
    }
}
