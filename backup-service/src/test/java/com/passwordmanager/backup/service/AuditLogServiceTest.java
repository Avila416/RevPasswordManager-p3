package com.passwordmanager.backup.service;

import com.passwordmanager.backup.dto.AuditLogRequest;
import com.passwordmanager.backup.dto.AuditLogResponse;
import com.passwordmanager.backup.entity.AuditLog;
import com.passwordmanager.backup.exception.AuditException;
import com.passwordmanager.backup.repository.AuditLogRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuditLogServiceTest {

    @Mock
    private AuditLogRepository auditLogRepository;

    private AuditLogService auditLogService;

    @BeforeEach
    void setUp() {
        auditLogService = new AuditLogService(auditLogRepository);
    }

    @Test
    void logTrimsFieldsAndSavesAuditRecord() {
        auditLogService.log(" BACKUP_EXPORT ", " 127.0.0.1 ", " SUCCESS ", 9L);

        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogRepository).save(captor.capture());
        AuditLog saved = captor.getValue();
        assertEquals("BACKUP_EXPORT", saved.getAction());
        assertEquals("127.0.0.1", saved.getIpAddress());
        assertEquals("SUCCESS", saved.getStatus());
        assertEquals(9L, saved.getUserId());
        assertNotNull(saved.getTimestamp());
    }

    @Test
    void logRejectsBlankRequiredFields() {
        AuditException exception = assertThrows(AuditException.class,
                () -> auditLogService.log(" ", "127.0.0.1", "SUCCESS", 1L));

        assertEquals("Action, IP, and status are required", exception.getMessage());
        verifyNoInteractions(auditLogRepository);
    }

    @Test
    void getLogsMapsEntitiesToResponses() {
        when(auditLogRepository.findAllByOrderByTimestampDesc()).thenReturn(List.of(
                AuditLog.builder()
                        .action("LOGIN")
                        .ipAddress("127.0.0.1")
                        .status("SUCCESS")
                        .timestamp(LocalDateTime.of(2026, 3, 11, 10, 15))
                        .build()
        ));

        List<AuditLogResponse> result = auditLogService.getLogs();

        assertEquals(1, result.size());
        assertEquals("LOGIN", result.get(0).getAction());
        assertEquals("127.0.0.1", result.get(0).getIp());
        assertEquals("SUCCESS", result.get(0).getStatus());
        assertEquals(LocalDateTime.of(2026, 3, 11, 10, 15), result.get(0).getTime());
    }

    @Test
    void logRequestDelegatesToEntityLogging() {
        AuditLogRequest request = new AuditLogRequest();
        request.setAction("RESTORE");
        request.setIp("10.0.0.1");
        request.setStatus("SUCCESS");
        request.setUserId(7L);

        auditLogService.log(request);

        verify(auditLogRepository).save(any(AuditLog.class));
    }

    @Test
    void getLogsByUserIdMapsEntitiesToResponses() {
        when(auditLogRepository.findByUserIdOrderByTimestampDesc(7L)).thenReturn(List.of(
                AuditLog.builder()
                        .action("RESTORE")
                        .ipAddress("10.0.0.1")
                        .status("FAILED")
                        .timestamp(LocalDateTime.of(2026, 3, 12, 9, 30))
                        .build()
        ));

        List<AuditLogResponse> result = auditLogService.getLogsByUserId(7L);

        assertEquals(1, result.size());
        assertEquals("RESTORE", result.get(0).getAction());
        assertEquals("FAILED", result.get(0).getStatus());
    }

    @Test
    void getLogsWrapsRepositoryFailures() {
        when(auditLogRepository.findAllByOrderByTimestampDesc()).thenThrow(new RuntimeException("db down"));

        AuditException exception = assertThrows(AuditException.class, () -> auditLogService.getLogs());

        assertEquals("Failed to fetch audit logs", exception.getMessage());
    }
}
