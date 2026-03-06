package com.passwordmanager.security.client;

import com.passwordmanager.security.dto.PasswordEntryDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;

@Component
public class VaultServiceClientFallback implements VaultServiceClient {

    private static final Logger log = LoggerFactory.getLogger(VaultServiceClientFallback.class);

    @Override
    public List<PasswordEntryDto> getUserPasswords(Long userId) {
        log.warn("Fallback: Unable to get passwords for user {}", userId);
        return Collections.emptyList();
    }

    @Override
    public long getPasswordCount(Long userId) {
        log.warn("Fallback: Unable to get password count for user {}", userId);
        return 0;
    }
}
