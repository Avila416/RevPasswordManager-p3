package com.passwordmanager.vault.client;

import com.passwordmanager.vault.dto.UserDto;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.Map;

@FeignClient(name = "auth-service", fallback = AuthServiceClientFallback.class)
public interface AuthServiceClient {

    @GetMapping("/api/users/{id}")
    UserDto getUserById(@PathVariable("id") Long id);

    @GetMapping("/api/users/exists/{id}")
    Boolean userExists(@PathVariable("id") Long id);

    @PostMapping("/api/users/{id}/master-password/verify")
    Map<String, Boolean> verifyMasterPassword(
            @PathVariable("id") Long id,
            @RequestBody Map<String, String> request);
}
