package com.passwordmanager.security.service;

import com.passwordmanager.security.client.VaultServiceClient;
import com.passwordmanager.security.dto.AlertResponse;
import com.passwordmanager.security.dto.AuditResponse;
import com.passwordmanager.security.dto.PasswordEntryDto;
import com.passwordmanager.security.dto.StoredPasswordAnalysisResponse;
import com.passwordmanager.security.entity.AuditReport;
import com.passwordmanager.security.entity.SecurityAlert;
import com.passwordmanager.security.repository.AuditReportRepository;
import com.passwordmanager.security.repository.SecurityAlertRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SecurityAuditServiceTest {

    @Mock
    private SecurityAlertRepository alertRepo;

    @Mock
    private AuditReportRepository auditReportRepository;

    @Mock
    private VaultServiceClient vaultServiceClient;

    private SecurityAuditService service;

    @BeforeEach
    void setUp() {
        service = new SecurityAuditService(alertRepo, auditReportRepository, new PasswordStrengthService(), vaultServiceClient);
    }

    @Test
    void generateAuditReturnsZeroSummaryForEmptyVault() {
        when(vaultServiceClient.getUserPasswords(1L, "master")).thenReturn(List.of());
        when(auditReportRepository.save(any(AuditReport.class))).thenAnswer(invocation -> {
            AuditReport report = invocation.getArgument(0);
            report.setId(100L);
            return report;
        });

        AuditResponse response = service.generateAudit(1L, "master");

        assertEquals(0, response.getTotal());
        assertEquals(0, response.getWeak());
        assertEquals(0, response.getReused());
        assertEquals(0, response.getOld());
        assertEquals(100L, response.getReportId());
    }

    @Test
    void generateAuditCountsWeakOldAndReusedPasswords() {
        PasswordEntryDto oldWeak = entry(1L, "alice", "gmail.com", "short", LocalDateTime.now().minusDays(120));
        PasswordEntryDto reusedOne = entry(2L, "bob", "github.com", "SamePass#123", LocalDateTime.now().minusDays(5));
        PasswordEntryDto reusedTwo = entry(3L, "charlie", "gitlab.com", "SamePass#123", LocalDateTime.now().minusDays(2));
        when(vaultServiceClient.getUserPasswords(2L, "master")).thenReturn(List.of(oldWeak, reusedOne, reusedTwo));
        when(auditReportRepository.save(any(AuditReport.class))).thenAnswer(invocation -> {
            AuditReport report = invocation.getArgument(0);
            report.setId(200L);
            return report;
        });
        when(alertRepo.existsByMessageAndTypeAndCreatedAtAfter(anyString(), anyString(), any())).thenReturn(false);

        AuditResponse response = service.generateAudit(2L, "master");

        assertEquals(3, response.getTotal());
        assertEquals(1, response.getWeak());
        assertEquals(2, response.getReused());
        assertEquals(1, response.getOld());
        assertEquals(3, response.getAlertCount());
        verify(alertRepo, times(3)).save(any(SecurityAlert.class));
    }

    @Test
    void analyzeStoredPasswordsFlagsWeakReusedAndOldEntries() {
        PasswordEntryDto oldWeak = entry(1L, "alice", "gmail.com", "short", LocalDateTime.now().minusDays(120));
        PasswordEntryDto reusedOne = entry(2L, "bob", "github.com", "SamePass#123", LocalDateTime.now().minusDays(5));
        PasswordEntryDto reusedTwo = entry(3L, "charlie", "gitlab.com", "SamePass#123", LocalDateTime.now().minusDays(2));
        when(vaultServiceClient.getUserPasswords(3L, "master")).thenReturn(List.of(oldWeak, reusedOne, reusedTwo));

        List<StoredPasswordAnalysisResponse> result = service.analyzeStoredPasswords(3L, "master");

        assertEquals(3, result.size());
        assertTrue(result.get(0).isWeak());
        assertTrue(result.get(0).isOld());
        assertTrue(result.get(1).isReused());
        assertTrue(result.get(2).isReused());
    }

    @Test
    void getRecentAlertsMapsEntitiesToResponses() {
        when(alertRepo.findTop100ByOrderByCreatedAtDesc()).thenReturn(List.of(
                SecurityAlert.builder()
                        .id(5L)
                        .message("Weak password detected")
                        .severity("HIGH")
                        .type("WEAK")
                        .createdAt(LocalDateTime.of(2026, 3, 12, 10, 0))
                        .build()
        ));

        List<AlertResponse> result = service.getRecentAlerts();

        assertEquals(1, result.size());
        assertEquals("Weak password detected", result.get(0).getMessage());
        assertEquals("HIGH", result.get(0).getSeverity());
    }

    @Test
    void clearAuditHistoryDeletesAlertsAndReports() {
        when(alertRepo.count()).thenReturn(4L);
        when(auditReportRepository.count()).thenReturn(2L);

        String message = service.clearAuditHistory();

        assertEquals("Deleted audit history. Alerts: 4, Reports: 2", message);
        verify(alertRepo).deleteAllInBatch();
        verify(auditReportRepository).deleteAllInBatch();
    }

    @Test
    void generateAuditFallbackReturnsEmptyResponse() {
        AuditResponse response = service.generateAuditFallback(7L, "master", new RuntimeException("down"));

        assertEquals(0, response.getTotal());
        assertEquals(0, response.getAlertCount());
        assertNull(response.getReportId());
    }

    @Test
    void analyzeStoredPasswordsFallbackReturnsEmptyList() {
        assertTrue(service.analyzeStoredPasswordsFallback(7L, "master", new RuntimeException("down")).isEmpty());
    }

    private PasswordEntryDto entry(Long id, String username, String website, String password, LocalDateTime createdAt) {
        PasswordEntryDto entry = new PasswordEntryDto();
        entry.setId(id);
        entry.setUsername(username);
        entry.setWebsite(website);
        entry.setEncryptedPassword(password);
        entry.setCreatedAt(createdAt);
        return entry;
    }
}
