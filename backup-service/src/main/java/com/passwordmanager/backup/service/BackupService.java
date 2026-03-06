package com.passwordmanager.backup.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.passwordmanager.backup.client.VaultServiceClient;
import com.passwordmanager.backup.dto.PasswordEntryDto;
import com.passwordmanager.backup.entity.BackupFile;
import com.passwordmanager.backup.exception.BackupException;
import com.passwordmanager.backup.repository.BackupFileRepository;
import com.passwordmanager.backup.util.AuditActions;
import com.passwordmanager.backup.util.EncryptionUtil;
import com.passwordmanager.backup.util.FileUtil;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class BackupService {

    private static final Logger log = LoggerFactory.getLogger(BackupService.class);

    private final BackupFileRepository backupFileRepository;
    private final VaultServiceClient vaultServiceClient;
    private final EncryptionUtil encryptionUtil;
    private final FileUtil fileUtil;
    private final AuditLogService auditLogService;
    private final ObjectMapper objectMapper;

    @Value("${backup.storage-path:./backups/}")
    private String backupStoragePath;

    public BackupService(BackupFileRepository backupFileRepository, VaultServiceClient vaultServiceClient,
                        EncryptionUtil encryptionUtil, FileUtil fileUtil, AuditLogService auditLogService,
                        ObjectMapper objectMapper) {
        this.backupFileRepository = backupFileRepository;
        this.vaultServiceClient = vaultServiceClient;
        this.encryptionUtil = encryptionUtil;
        this.fileUtil = fileUtil;
        this.auditLogService = auditLogService;
        this.objectMapper = objectMapper;
    }

    @CircuitBreaker(name = "vaultService", fallbackMethod = "exportBackupFallback")
    public String exportBackup(Long userId) {
        List<PasswordEntryDto> entries = vaultServiceClient.exportUserVault(userId);
        String vaultSnapshot = serializeVaultSnapshot(entries);
        String encrypted = encryptionUtil.encrypt(vaultSnapshot);
        String checksum = sha256(encrypted);
        String payload = checksum + "." + encrypted;

        String fileName = "vault-backup-" + userId + "-" + System.currentTimeMillis() + ".bkp";
        BackupFile backupFile = BackupFile.builder()
                .fileName(fileName)
                .encryptedContent(encrypted)
                .checksum(checksum)
                .userId(userId)
                .createdAt(LocalDateTime.now())
                .build();
        backupFileRepository.save(backupFile);

        auditLogService.log(AuditActions.BACKUP_EXPORT, "127.0.0.1", "SUCCESS", userId);
        return payload;
    }

    public String exportBackupFallback(Long userId, Throwable throwable) {
        log.warn("Fallback triggered for exportBackup. User: {}, Error: {}", userId, throwable.getMessage());
        auditLogService.log(AuditActions.BACKUP_EXPORT, "127.0.0.1", "FAILED", userId);
        throw new BackupException("Unable to export backup - vault service unavailable");
    }

    public Map<String, Object> restoreBackup(String fileContent, Long userId) {
        if (!isValidPayload(fileContent)) {
            auditLogService.log(AuditActions.BACKUP_RESTORE, "127.0.0.1", "FAILED", userId);
            throw new BackupException("Invalid backup content");
        }

        String encrypted = getEncryptedSegment(fileContent);
        String decrypted;
        try {
            decrypted = encryptionUtil.decrypt(encrypted);
        } catch (Exception ex) {
            auditLogService.log(AuditActions.BACKUP_RESTORE, "127.0.0.1", "FAILED", userId);
            throw new BackupException("Unable to decrypt backup content");
        }

        // Parse and validate entries
        List<PasswordEntryDto> entries = parseVaultSnapshot(decrypted);

        auditLogService.log(AuditActions.BACKUP_RESTORE, "127.0.0.1", "SUCCESS", userId);
        return Map.of(
                "message", "Backup validated successfully. Ready for restore.",
                "entryCount", entries.size(),
                "validatedAt", LocalDateTime.now().toString()
        );
    }

    public Map<String, Object> updateBackup(String fileContent, Long userId) {
        if (!isValidPayload(fileContent)) {
            auditLogService.log(AuditActions.BACKUP_UPDATE, "127.0.0.1", "FAILED", userId);
            throw new BackupException("Invalid backup content");
        }

        Optional<BackupFile> latestOpt = backupFileRepository.findTopByUserIdOrderByCreatedAtDesc(userId);
        if (latestOpt.isEmpty()) {
            auditLogService.log(AuditActions.BACKUP_UPDATE, "127.0.0.1", "FAILED", userId);
            throw new BackupException("No backup found to update");
        }

        BackupFile latest = latestOpt.get();
        latest.setEncryptedContent(getEncryptedSegment(fileContent));
        latest.setChecksum(getChecksumSegment(fileContent));
        latest.setCreatedAt(LocalDateTime.now());
        backupFileRepository.save(latest);

        auditLogService.log(AuditActions.BACKUP_UPDATE, "127.0.0.1", "SUCCESS", userId);
        return Map.of(
                "message", "Backup updated successfully",
                "fileName", latest.getFileName(),
                "checksum", latest.getChecksum(),
                "updatedAt", latest.getCreatedAt().toString()
        );
    }

    public Map<String, Object> validateBackup(String fileContent, Long userId) {
        boolean valid = isValidPayload(fileContent);
        auditLogService.log(AuditActions.BACKUP_VALIDATE, "127.0.0.1", valid ? "SUCCESS" : "FAILED", userId);

        if (!valid) {
            throw new BackupException("Backup integrity validation failed");
        }

        String checksum = getChecksumSegment(fileContent);
        String encrypted = getEncryptedSegment(fileContent);
        return Map.of(
                "message", "Backup file validated successfully",
                "checksum", checksum,
                "encryptedLength", encrypted.length(),
                "payloadLength", fileContent.length(),
                "validatedAt", LocalDateTime.now().toString()
        );
    }

    public String deleteBackup(Long userId) {
        Optional<BackupFile> latestOpt = backupFileRepository.findTopByUserIdOrderByCreatedAtDesc(userId);
        if (latestOpt.isEmpty()) {
            auditLogService.log(AuditActions.BACKUP_DELETE, "127.0.0.1", "FAILED", userId);
            throw new BackupException("No backup found to delete");
        }

        BackupFile latest = latestOpt.get();
        backupFileRepository.deleteById(latest.getId());
        auditLogService.log(AuditActions.BACKUP_DELETE, "127.0.0.1", "SUCCESS", userId);
        return "Backup deleted successfully";
    }

    public Map<String, Object> latestBackupInfo(Long userId) {
        Optional<BackupFile> latestOpt = backupFileRepository.findTopByUserIdOrderByCreatedAtDesc(userId);
        if (latestOpt.isEmpty()) {
            return Map.of(
                    "exists", false,
                    "fileName", "",
                    "createdAt", ""
            );
        }

        BackupFile latest = latestOpt.get();
        return Map.of(
                "exists", true,
                "fileName", latest.getFileName(),
                "checksum", latest.getChecksum(),
                "createdAt", latest.getCreatedAt() == null ? "" : latest.getCreatedAt().toString()
        );
    }

    private String serializeVaultSnapshot(List<PasswordEntryDto> entries) {
        try {
            return objectMapper.writeValueAsString(entries);
        } catch (Exception ex) {
            throw new BackupException("Unable to generate backup payload");
        }
    }

    private List<PasswordEntryDto> parseVaultSnapshot(String decryptedPayload) {
        try {
            return objectMapper.readValue(decryptedPayload, new TypeReference<>() {});
        } catch (Exception ex) {
            throw new BackupException("Unable to parse backup content");
        }
    }

    private boolean isValidPayload(String fileContent) {
        if (!fileUtil.validate(fileContent) || !fileContent.contains(".")) {
            return false;
        }
        String checksum = getChecksumSegment(fileContent);
        String encrypted = getEncryptedSegment(fileContent);
        if (!fileUtil.validate(checksum) || !fileUtil.validate(encrypted)) {
            return false;
        }
        if (!checksum.equals(sha256(encrypted))) {
            return false;
        }

        try {
            encryptionUtil.decrypt(encrypted);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    private String getChecksumSegment(String fileContent) {
        return fileContent.substring(0, fileContent.indexOf('.'));
    }

    private String getEncryptedSegment(String fileContent) {
        return fileContent.substring(fileContent.indexOf('.') + 1);
    }

    private String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException ex) {
            throw new BackupException("Unable to compute backup checksum");
        }
    }
}
