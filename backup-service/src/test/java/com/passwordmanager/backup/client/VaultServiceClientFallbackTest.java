package com.passwordmanager.backup.client;

import com.passwordmanager.backup.dto.PasswordEntryDto;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class VaultServiceClientFallbackTest {

    private final VaultServiceClientFallback fallback = new VaultServiceClientFallback();

    @Test
    void exportUserVaultReturnsEmptyList() {
        List<PasswordEntryDto> result = fallback.exportUserVault(7L, "master");

        assertTrue(result.isEmpty());
    }

    @Test
    void getUserPasswordsReturnsEmptyList() {
        List<PasswordEntryDto> result = fallback.getUserPasswords(7L, "master");

        assertTrue(result.isEmpty());
    }

    @Test
    void restoreUserVaultReturnsUnavailableMessage() {
        Map<String, Object> result = fallback.restoreUserVault(7L, List.of());

        assertEquals("Vault service unavailable", result.get("message"));
        assertEquals(0, result.get("restoredCount"));
    }
}
