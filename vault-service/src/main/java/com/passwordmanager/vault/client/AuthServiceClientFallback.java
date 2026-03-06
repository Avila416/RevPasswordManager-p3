package com.passwordmanager.vault.client;

import com.passwordmanager.vault.dto.UserDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class AuthServiceClientFallback implements AuthServiceClient {

    private static final Logger log = LoggerFactory.getLogger(AuthServiceClientFallback.class);

    @Override
    public UserDto getUserById(Long id) {
        log.warn("Fallback: Auth service unavailable, returning default user for id: {}", id);
        return UserDto.builder()
                .id(id)
                .username("unknown")
                .email("unknown@example.com")
                .build();
    }

    @Override
    public Boolean userExists(Long id) {
        log.warn("Fallback: Auth service unavailable, assuming user exists for id: {}", id);
        return true;
    }
}
