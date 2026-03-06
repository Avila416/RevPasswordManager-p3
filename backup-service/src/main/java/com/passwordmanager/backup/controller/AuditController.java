package com.passwordmanager.backup.controller;

import com.passwordmanager.backup.dto.AuditLogRequest;
import com.passwordmanager.backup.dto.AuditLogResponse;
import com.passwordmanager.backup.service.AuditLogService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Size;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/audit")
@Validated
@CrossOrigin(origins = "*")
public class AuditController {

    private final AuditLogService service;

    public AuditController(AuditLogService service) {
        this.service = service;
    }

    @GetMapping
    public List<AuditLogResponse> logs(
            @RequestParam(required = false) @Size(max = 80, message = "Action filter is too long") String action,
            @RequestParam(required = false) @Size(max = 30, message = "Status filter is too long") String status,
            @RequestParam(required = false) @Size(max = 45, message = "IP filter is too long") String ip) {
        String normalizedAction = normalize(action);
        String normalizedStatus = normalize(status);
        String normalizedIp = normalize(ip);

        return service.getLogs().stream()
                .filter(log -> normalizedAction == null || normalize(log.getAction()).contains(normalizedAction))
                .filter(log -> normalizedStatus == null || normalize(log.getStatus()).contains(normalizedStatus))
                .filter(log -> normalizedIp == null || normalize(log.getIp()).contains(normalizedIp))
                .collect(Collectors.toList());
    }

    @PostMapping("/log")
    public void logAction(@Valid @RequestBody AuditLogRequest request) {
        service.log(request);
    }

    private String normalize(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        return trimmed.toLowerCase(Locale.ROOT);
    }
}
