package com.passwordmanager.backup.service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

import com.passwordmanager.backup.dto.AuditLogRequest;
import com.passwordmanager.backup.dto.AuditLogResponse;
import com.passwordmanager.backup.entity.AuditLog;
import com.passwordmanager.backup.exception.AuditException;
import com.passwordmanager.backup.repository.AuditLogRepository;

@Service
public class AuditLogService {

    private final AuditLogRepository auditLogRepository;

    public AuditLogService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    public void log(String action, String ip, String status, Long userId) {
        if (isBlank(action) || isBlank(ip) || isBlank(status)) {
            throw new AuditException("Action, IP, and status are required");
        }

        try {
            AuditLog auditLog = AuditLog.builder()
                    .action(action.trim())
                    .ipAddress(ip.trim())
                    .status(status.trim())
                    .userId(userId)
                    .timestamp(LocalDateTime.now())
                    .build();
            auditLogRepository.save(auditLog);
        } catch (Exception ex) {
            throw new AuditException("Failed to save audit log");
        }
    }

    public void log(AuditLogRequest request) {
        log(request.getAction(), request.getIp(), request.getStatus(), request.getUserId());
    }

    public List<AuditLogResponse> getLogs() {
        try {
            return auditLogRepository.findAllByOrderByTimestampDesc()
                    .stream()
                    .map(a -> new AuditLogResponse(a.getAction(), a.getIpAddress(), a.getStatus(), a.getTimestamp()))
                    .collect(Collectors.toList());
        } catch (Exception ex) {
            throw new AuditException("Failed to fetch audit logs");
        }
    }

    public List<AuditLogResponse> getLogsByUserId(Long userId) {
        try {
            return auditLogRepository.findByUserIdOrderByTimestampDesc(userId)
                    .stream()
                    .map(a -> new AuditLogResponse(a.getAction(), a.getIpAddress(), a.getStatus(), a.getTimestamp()))
                    .collect(Collectors.toList());
        } catch (Exception ex) {
            throw new AuditException("Failed to fetch audit logs");
        }
    }

    private boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }
}
