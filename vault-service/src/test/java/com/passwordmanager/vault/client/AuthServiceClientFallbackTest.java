package com.passwordmanager.vault.client;

import com.passwordmanager.vault.dto.UserDto;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AuthServiceClientFallbackTest {

    private final AuthServiceClientFallback fallback = new AuthServiceClientFallback();

    @Test
    void getUserByIdReturnsDefaultUser() {
        UserDto user = fallback.getUserById(8L);

        assertEquals(8L, user.getId());
        assertEquals("unknown", user.getUsername());
    }

    @Test
    void userExistsReturnsTrue() {
        assertTrue(fallback.userExists(8L));
    }

    @Test
    void verifyMasterPasswordReturnsFalse() {
        assertEquals(Map.of("valid", false), fallback.verifyMasterPassword(8L, Map.of("masterPassword", "x")));
    }
}
