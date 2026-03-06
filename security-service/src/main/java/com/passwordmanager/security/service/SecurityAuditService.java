package com.passwordmanager.security.service;

import com.passwordmanager.security.client.VaultServiceClient;
import com.passwordmanager.security.dto.*;
import com.passwordmanager.security.entity.AuditReport;
import com.passwordmanager.security.entity.SecurityAlert;
import com.passwordmanager.security.repository.AuditReportRepository;
import com.passwordmanager.security.repository.SecurityAlertRepository;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class SecurityAuditService {

    private static final Logger log = LoggerFactory.getLogger(SecurityAuditService.class);

    private final SecurityAlertRepository alertRepo;
    private final AuditReportRepository auditReportRepository;
    private final PasswordStrengthService strengthService;
    private final VaultServiceClient vaultServiceClient;

    public SecurityAuditService(SecurityAlertRepository alertRepo, AuditReportRepository auditReportRepository,
                                PasswordStrengthService strengthService, VaultServiceClient vaultServiceClient) {
        this.alertRepo = alertRepo;
        this.auditReportRepository = auditReportRepository;
        this.strengthService = strengthService;
        this.vaultServiceClient = vaultServiceClient;
    }

    @CircuitBreaker(name = "vaultService", fallbackMethod = "generateAuditFallback")
    public AuditResponse generateAudit(Long userId) {
        List<PasswordEntryDto> list = vaultServiceClient.getUserPasswords(userId);

        if (list == null || list.isEmpty()) {
            LocalDateTime generatedAt = LocalDateTime.now();
            AuditReport savedReport = auditReportRepository.save(
                    AuditReport.builder()
                            .totalPasswords(0)
                            .weakPasswords(0)
                            .reusedPasswords(0)
                            .oldPasswords(0)
                            .generatedAt(generatedAt)
                            .build()
            );

            return AuditResponse.builder()
                    .total(0)
                    .weak(0)
                    .reused(0)
                    .old(0)
                    .reportId(savedReport.getId())
                    .alertCount(0)
                    .generatedAt(generatedAt)
                    .build();
        }

        int weak = 0;
        int reused = 0;
        int old = 0;
        int alertsCreated = 0;
        Map<String, Integer> passwordUseMap = new HashMap<>();
        Map<String, List<PasswordEntryDto>> passwordEntriesMap = new HashMap<>();

        for (PasswordEntryDto entry : list) {
            String password = entry.getEncryptedPassword() != null ? entry.getEncryptedPassword() : "";
            String strength = strengthService.checkStrength(password);

            if ("WEAK".equalsIgnoreCase(strength)) {
                weak++;
                if (saveAlert("Weak password detected for: " + safeLabel(entry), "WEAK", "HIGH")) {
                    alertsCreated++;
                }
            }

            if (!password.isBlank()) {
                passwordUseMap.put(password, passwordUseMap.getOrDefault(password, 0) + 1);
                passwordEntriesMap.computeIfAbsent(password, k -> new ArrayList<>()).add(entry);
            }

            if (entry.getCreatedAt() != null &&
                    entry.getCreatedAt().isBefore(LocalDateTime.now().minusDays(90))) {
                old++;
                if (saveAlert("Old password detected for: " + safeLabel(entry), "OLD", "MEDIUM")) {
                    alertsCreated++;
                }
            }
        }

        for (Map.Entry<String, Integer> mapEntry : passwordUseMap.entrySet()) {
            int count = mapEntry.getValue();
            if (count > 1) {
                reused += count;
                String usageDetails = usageDetails(passwordEntriesMap.getOrDefault(mapEntry.getKey(), List.of()));
                String message = "Reused password detected (" + count + " occurrences)";
                if (!usageDetails.isBlank()) {
                    message += ". Used by: " + usageDetails;
                }
                if (saveAlert(message, "REUSED", "HIGH")) {
                    alertsCreated++;
                }
            }
        }

        LocalDateTime generatedAt = LocalDateTime.now();
        AuditReport savedReport = auditReportRepository.save(
                AuditReport.builder()
                        .totalPasswords(list.size())
                        .weakPasswords(weak)
                        .reusedPasswords(reused)
                        .oldPasswords(old)
                        .generatedAt(generatedAt)
                        .build()
        );

        return AuditResponse.builder()
                .total(list.size())
                .weak(weak)
                .reused(reused)
                .old(old)
                .reportId(savedReport.getId())
                .alertCount(alertsCreated)
                .generatedAt(generatedAt)
                .build();
    }

    public AuditResponse generateAuditFallback(Long userId, Throwable throwable) {
        log.warn("Fallback triggered for generateAudit. User: {}, Error: {}", userId, throwable.getMessage());
        return AuditResponse.builder()
                .total(0)
                .weak(0)
                .reused(0)
                .old(0)
                .reportId(null)
                .alertCount(0)
                .generatedAt(LocalDateTime.now())
                .build();
    }

    public List<AlertResponse> getRecentAlerts() {
        return alertRepo.findTop100ByOrderByCreatedAtDesc()
                .stream()
                .map(this::toAlertResponse)
                .toList();
    }

    @CircuitBreaker(name = "vaultService", fallbackMethod = "analyzeStoredPasswordsFallback")
    public List<StoredPasswordAnalysisResponse> analyzeStoredPasswords(Long userId) {
        List<PasswordEntryDto> list = vaultServiceClient.getUserPasswords(userId);
        Map<String, Integer> useMap = new HashMap<>();

        for (PasswordEntryDto entry : list) {
            String password = entry.getEncryptedPassword() != null ? entry.getEncryptedPassword() : "";
            if (!password.isBlank()) {
                useMap.put(password, useMap.getOrDefault(password, 0) + 1);
            }
        }

        return list.stream()
                .map(entry -> toAnalysisResponse(entry, useMap))
                .toList();
    }

    public List<StoredPasswordAnalysisResponse> analyzeStoredPasswordsFallback(Long userId, Throwable throwable) {
        log.warn("Fallback triggered for analyzeStoredPasswords. User: {}, Error: {}", userId, throwable.getMessage());
        return Collections.emptyList();
    }

    public String clearAuditHistory() {
        long alertCount = alertRepo.count();
        long reportCount = auditReportRepository.count();

        alertRepo.deleteAllInBatch();
        auditReportRepository.deleteAllInBatch();

        return "Deleted audit history. Alerts: " + alertCount + ", Reports: " + reportCount;
    }

    private StoredPasswordAnalysisResponse toAnalysisResponse(PasswordEntryDto entry, Map<String, Integer> useMap) {
        String password = entry.getEncryptedPassword() != null ? entry.getEncryptedPassword() : "";
        String strength = strengthService.checkStrength(password);
        boolean isOld = entry.getCreatedAt() != null &&
                entry.getCreatedAt().isBefore(LocalDateTime.now().minusDays(90));
        boolean isReused = !password.isBlank() && useMap.getOrDefault(password, 0) > 1;
        boolean isWeak = "WEAK".equalsIgnoreCase(strength);

        return StoredPasswordAnalysisResponse.builder()
                .entryId(entry.getId())
                .username(entry.getUsername())
                .website(entry.getWebsite())
                .strength(strength)
                .weak(isWeak)
                .reused(isReused)
                .old(isOld)
                .createdAt(entry.getCreatedAt())
                .build();
    }

    private AlertResponse toAlertResponse(SecurityAlert alert) {
        return AlertResponse.builder()
                .id(alert.getId())
                .message(alert.getMessage())
                .severity(alert.getSeverity())
                .type(alert.getType())
                .createdAt(alert.getCreatedAt())
                .build();
    }

    private String safeLabel(PasswordEntryDto entry) {
        String username = entry.getUsername() == null ? "" : entry.getUsername().trim();
        String website = entry.getWebsite() == null ? "" : entry.getWebsite().trim();

        if (!username.isBlank() && !website.isBlank()) {
            return username + " @ " + website;
        }
        if (!username.isBlank()) {
            return username;
        }
        if (!website.isBlank()) {
            return website;
        }
        return "entry#" + entry.getId();
    }

    private String usageDetails(List<PasswordEntryDto> entries) {
        Set<String> labels = new LinkedHashSet<>();
        for (PasswordEntryDto entry : entries) {
            labels.add(safeLabel(entry));
        }

        if (labels.isEmpty()) {
            return "";
        }

        List<String> list = new ArrayList<>(labels);
        int limit = Math.min(5, list.size());
        String joined = String.join(", ", list.subList(0, limit));
        if (list.size() > limit) {
            joined += " +" + (list.size() - limit) + " more";
        }
        return joined;
    }

    private boolean saveAlert(String msg, String type, String severity) {
        LocalDateTime now = LocalDateTime.now();
        boolean duplicateRecent = alertRepo.existsByMessageAndTypeAndCreatedAtAfter(
                msg,
                type,
                now.minusHours(24)
        );
        if (duplicateRecent) {
            return false;
        }

        alertRepo.save(
                SecurityAlert.builder()
                        .message(msg)
                        .type(type)
                        .severity(severity)
                        .createdAt(now)
                        .build()
        );
        return true;
    }
}
