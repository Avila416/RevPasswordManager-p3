package com.passwordmanager.security.service;

import com.passwordmanager.security.client.VaultServiceClient;
import com.passwordmanager.security.dto.DashboardResponse;
import com.passwordmanager.security.dto.PasswordEntryDto;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@Service
public class DashboardService {

    private static final Logger log = LoggerFactory.getLogger(DashboardService.class);

    private final VaultServiceClient vaultServiceClient;
    private final PasswordStrengthService strengthService;

    public DashboardService(VaultServiceClient vaultServiceClient, PasswordStrengthService strengthService) {
        this.vaultServiceClient = vaultServiceClient;
        this.strengthService = strengthService;
    }

    @CircuitBreaker(name = "vaultService", fallbackMethod = "getDashboardFallback")
    public DashboardResponse getDashboard(Long userId) {
        List<PasswordEntryDto> passwords = vaultServiceClient.getUserPasswords(userId);

        long totalPasswords = passwords.size();
        long recentPasswords = passwords.stream()
                .filter(p -> p.getCreatedAt() != null && p.getCreatedAt().isAfter(LocalDateTime.now().minusDays(7)))
                .count();
        long weakPasswords = passwords.stream()
                .filter(p -> isWeak(p.getEncryptedPassword()))
                .count();

        return new DashboardResponse(totalPasswords, weakPasswords, recentPasswords, Collections.emptyMap());
    }

    public DashboardResponse getDashboardFallback(Long userId, Throwable throwable) {
        log.warn("Fallback triggered for getDashboard. User: {}, Error: {}", userId, throwable.getMessage());
        return new DashboardResponse(0, 0, 0, Collections.emptyMap());
    }

    private boolean isWeak(String password) {
        if (password == null || password.length() < 8) {
            return true;
        }
        String strength = strengthService.checkStrength(password);
        return "WEAK".equalsIgnoreCase(strength);
    }
}
