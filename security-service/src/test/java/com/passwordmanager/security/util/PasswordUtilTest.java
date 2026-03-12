package com.passwordmanager.security.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PasswordUtilTest {

    private final PasswordUtil passwordUtil = new PasswordUtil();

    @Test
    void generateIncludesRequestedCharacterTypes() {
        String password = passwordUtil.generate(16, true, true, true, true, false);

        assertEquals(16, password.length());
        assertTrue(password.matches(".*[A-Z].*"));
        assertTrue(password.matches(".*[a-z].*"));
        assertTrue(password.matches(".*[0-9].*"));
        assertTrue(password.matches(".*[@#$%&*!?].*"));
    }

    @Test
    void generateRejectsTooShortLengthForSelectedTypes() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> passwordUtil.generate(1, true, true, false, false, false));

        assertEquals("Length is too short for selected character types", exception.getMessage());
    }
}
