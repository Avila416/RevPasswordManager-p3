package com.passwordmanager.backup.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.passwordmanager.backup.client.VaultServiceClient;
import com.passwordmanager.backup.dto.PasswordEntryDto;
import com.passwordmanager.backup.entity.BackupFile;
import com.passwordmanager.backup.exception.BackupException;
import com.passwordmanager.backup.repository.BackupFileRepository;
import com.passwordmanager.backup.util.AuditActions;
import com.passwordmanager.backup.util.EncryptionUtil;
import com.passwordmanager.backup.util.FileUtil;
import feign.FeignException;
import feign.Request;
import feign.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class BackupServiceTest {

    @Mock
    private BackupFileRepository backupFileRepository;

    @Mock
    private VaultServiceClient vaultServiceClient;

    @Mock
    private AuditLogService auditLogService;

    private BackupService backupService;

    @BeforeEach
    void setUp() {
        EncryptionUtil encryptionUtil = new EncryptionUtil();
        ReflectionTestUtils.setField(encryptionUtil, "encryptionKey", "BackupEncryptionSecretKey1234567");
        backupService = new BackupService(
                backupFileRepository,
                vaultServiceClient,
                encryptionUtil,
                new FileUtil(),
                auditLogService,
                new ObjectMapper()
        );
    }

    @Test
    void exportBackupPersistsEncryptedPayloadAndReturnsChecksumWrappedPayload() {
        PasswordEntryDto entry = new PasswordEntryDto();
        entry.setId(5L);
        entry.setWebsite("example.com");
        entry.setEncryptedPassword("enc-secret");
        when(vaultServiceClient.exportUserVault(11L, "master")).thenReturn(List.of(entry));

        String payload = backupService.exportBackup(11L, "master");

        String[] parts = payload.split("\\.", 2);
        assertEquals(2, parts.length);
        assertEquals(64, parts[0].length());
        assertTrue(parts[1].startsWith("v1:"));

        ArgumentCaptor<BackupFile> captor = ArgumentCaptor.forClass(BackupFile.class);
        verify(backupFileRepository).save(captor.capture());
        BackupFile saved = captor.getValue();
        assertEquals(11L, saved.getUserId());
        assertEquals(parts[0], saved.getChecksum());
        assertEquals(parts[1], saved.getEncryptedContent());
        assertNotNull(saved.getCreatedAt());
        verify(auditLogService).log(AuditActions.BACKUP_EXPORT, "127.0.0.1", "SUCCESS", 11L);
    }

    @Test
    void exportBackupRequiresMasterPassword() {
        BackupException exception = assertThrows(BackupException.class,
                () -> backupService.exportBackup(11L, " "));

        assertEquals("Master password is required", exception.getMessage());
        verify(auditLogService).log(AuditActions.BACKUP_EXPORT, "127.0.0.1", "FAILED", 11L);
        verifyNoInteractions(vaultServiceClient, backupFileRepository);
    }

    @Test
    void exportBackupFallbackUsesMessageFromBadRequestPayload() {
        Response response = Response.builder()
                .status(400)
                .reason("Bad Request")
                .request(Request.create(Request.HttpMethod.GET, "/api/vault/user/1/export", Map.of(), null, StandardCharsets.UTF_8, null))
                .body("{\"message\":\"Master password is invalid\"}", StandardCharsets.UTF_8)
                .build();
        FeignException exception = FeignException.errorStatus("VaultServiceClient#exportUserVault", response);

        BackupException thrown = assertThrows(BackupException.class,
                () -> backupService.exportBackupFallback(1L, "bad", exception));

        assertEquals("Master password is invalid", thrown.getMessage());
        verify(auditLogService).log(AuditActions.BACKUP_EXPORT, "127.0.0.1", "FAILED", 1L);
    }

    @Test
    void exportBackupFallbackReturnsUnavailableMessageForGenericFailure() {
        BackupException exception = assertThrows(BackupException.class,
                () -> backupService.exportBackupFallback(5L, "master", new RuntimeException("down")));

        assertEquals("Unable to export backup - vault service unavailable", exception.getMessage());
        verify(auditLogService).log(AuditActions.BACKUP_EXPORT, "127.0.0.1", "FAILED", 5L);
    }

    @Test
    void restoreBackupDecryptsPayloadAndReturnsRestoreSummary() throws Exception {
        PasswordEntryDto entry = new PasswordEntryDto();
        entry.setId(3L);
        entry.setWebsite("example.com");
        entry.setEncryptedPassword("enc");
        String encrypted = encryptPayload(List.of(entry));
        String payload = sha256(encrypted) + "." + encrypted;
        when(vaultServiceClient.restoreUserVault(eq(3L), anyList()))
                .thenReturn(Map.of("message", "ok", "restoredCount", 1));

        Map<String, Object> result = backupService.restoreBackup(payload, 3L);

        assertEquals("Backup restored successfully", result.get("message"));
        assertEquals(1L, result.get("restoredEntries"));
        assertTrue(result.containsKey("restoredAt"));
        verify(auditLogService).log(AuditActions.BACKUP_RESTORE, "127.0.0.1", "SUCCESS", 3L);
    }

    @Test
    void restoreBackupRejectsInvalidPayload() {
        BackupException exception = assertThrows(BackupException.class,
                () -> backupService.restoreBackup("not-a-valid-payload", 8L));

        assertEquals("Invalid backup content", exception.getMessage());
        verify(auditLogService).log(AuditActions.BACKUP_RESTORE, "127.0.0.1", "FAILED", 8L);
    }

    @Test
    void validateBackupRejectsTamperedPayload() throws Exception {
        PasswordEntryDto entry = new PasswordEntryDto();
        entry.setId(8L);
        String encrypted = encryptPayload(List.of(entry));
        String invalidPayload = "deadbeef." + encrypted;

        BackupException exception = assertThrows(BackupException.class,
                () -> backupService.validateBackup(invalidPayload, 8L));

        assertEquals("Backup integrity validation failed", exception.getMessage());
        verify(auditLogService).log(AuditActions.BACKUP_VALIDATE, "127.0.0.1", "FAILED", 8L);
    }

    @Test
    void updateBackupFailsWhenNoStoredBackupExists() throws Exception {
        PasswordEntryDto entry = new PasswordEntryDto();
        entry.setId(12L);
        String encrypted = encryptPayload(List.of(entry));
        String payload = sha256(encrypted) + "." + encrypted;
        when(backupFileRepository.findTopByUserIdOrderByCreatedAtDesc(9L)).thenReturn(Optional.empty());

        BackupException exception = assertThrows(BackupException.class,
                () -> backupService.updateBackup(payload, 9L));

        assertEquals("No backup found to update", exception.getMessage());
        verify(auditLogService).log(AuditActions.BACKUP_UPDATE, "127.0.0.1", "FAILED", 9L);
    }

    @Test
    void deleteBackupFailsWhenNoBackupExists() {
        when(backupFileRepository.findTopByUserIdOrderByCreatedAtDesc(4L)).thenReturn(Optional.empty());

        BackupException exception = assertThrows(BackupException.class,
                () -> backupService.deleteBackup(4L));

        assertEquals("No backup found to delete", exception.getMessage());
        verify(auditLogService).log(AuditActions.BACKUP_DELETE, "127.0.0.1", "FAILED", 4L);
    }

    @Test
    void latestBackupInfoReturnsExistingFileMetadata() {
        BackupFile file = BackupFile.builder()
                .id(1L)
                .fileName("vault-backup-1.bkp")
                .checksum("abc123")
                .encryptedContent("v1:payload")
                .userId(1L)
                .createdAt(LocalDateTime.of(2026, 3, 11, 9, 0))
                .build();
        when(backupFileRepository.findTopByUserIdOrderByCreatedAtDesc(1L)).thenReturn(Optional.of(file));

        Map<String, Object> result = backupService.latestBackupInfo(1L);

        assertEquals(true, result.get("exists"));
        assertEquals("vault-backup-1.bkp", result.get("fileName"));
        assertEquals("abc123", result.get("checksum"));
        assertEquals("2026-03-11T09:00", result.get("createdAt"));
    }

    @Test
    void latestBackupInfoReturnsEmptyMetadataWhenMissing() {
        when(backupFileRepository.findTopByUserIdOrderByCreatedAtDesc(15L)).thenReturn(Optional.empty());

        Map<String, Object> result = backupService.latestBackupInfo(15L);

        assertEquals(false, result.get("exists"));
        assertEquals("", result.get("fileName"));
        assertEquals("", result.get("createdAt"));
    }

    private String encryptPayload(List<PasswordEntryDto> entries) throws Exception {
        EncryptionUtil encryptionUtil = new EncryptionUtil();
        ReflectionTestUtils.setField(encryptionUtil, "encryptionKey", "BackupEncryptionSecretKey1234567");
        return encryptionUtil.encrypt(new ObjectMapper().writeValueAsString(entries));
    }

    private String sha256(String value) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
