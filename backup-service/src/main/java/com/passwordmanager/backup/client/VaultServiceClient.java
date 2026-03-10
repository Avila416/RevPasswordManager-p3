package com.passwordmanager.backup.client;

import com.passwordmanager.backup.dto.PasswordEntryDto;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

import java.util.List;
import java.util.Map;

@FeignClient(name = "vault-service", fallback = VaultServiceClientFallback.class)
public interface VaultServiceClient {

    @GetMapping("/api/vault/user/{userId}/export")
    List<PasswordEntryDto> exportUserVault(
            @PathVariable("userId") Long userId,
            @RequestHeader("X-Master-Password") String masterPassword);

    @GetMapping("/api/vault/user/{userId}")
    List<PasswordEntryDto> getUserPasswords(
            @PathVariable("userId") Long userId,
            @RequestHeader("X-Master-Password") String masterPassword);

    @PostMapping("/api/vault/user/{userId}/restore")
    Map<String, Object> restoreUserVault(@PathVariable("userId") Long userId, @RequestBody List<PasswordEntryDto> entries);
}
