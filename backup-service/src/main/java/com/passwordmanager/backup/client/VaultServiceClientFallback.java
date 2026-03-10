package com.passwordmanager.backup.client;

import com.passwordmanager.backup.dto.PasswordEntryDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;
import java.util.Map;

@Component
public class VaultServiceClientFallback implements VaultServiceClient {

    private static final Logger log = LoggerFactory.getLogger(VaultServiceClientFallback.class);

    @Override
    public List<PasswordEntryDto> exportUserVault(Long userId, String masterPassword) {
        log.warn("Fallback: Unable to export vault for user {}", userId);
        return Collections.emptyList();
    }

    @Override
    public List<PasswordEntryDto> getUserPasswords(Long userId, String masterPassword) {
        log.warn("Fallback: Unable to get passwords for user {}", userId);
        return Collections.emptyList();
    }

    @Override
    public Map<String, Object> restoreUserVault(Long userId, List<PasswordEntryDto> entries) {
        log.warn("Fallback: Unable to restore vault for user {}", userId);
        return Map.of("message", "Vault service unavailable", "restoredCount", 0);
    }
}
