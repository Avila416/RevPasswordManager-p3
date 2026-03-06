package com.passwordmanager.backup.client;

import com.passwordmanager.backup.dto.PasswordEntryDto;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import java.util.List;

@FeignClient(name = "vault-service", fallback = VaultServiceClientFallback.class)
public interface VaultServiceClient {

    @GetMapping("/api/vault/user/{userId}/export")
    List<PasswordEntryDto> exportUserVault(@PathVariable("userId") Long userId);

    @GetMapping("/api/vault/user/{userId}")
    List<PasswordEntryDto> getUserPasswords(@PathVariable("userId") Long userId);
}
