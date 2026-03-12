package com.passwordmanager.security.client;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class VaultServiceClientFallbackTest {

    private final VaultServiceClientFallback fallback = new VaultServiceClientFallback();

    @Test
    void getUserPasswordsReturnsEmptyList() {
        assertTrue(fallback.getUserPasswords(1L, "master").isEmpty());
    }

    @Test
    void getPasswordCountReturnsZero() {
        assertEquals(0L, fallback.getPasswordCount(1L));
    }
}
