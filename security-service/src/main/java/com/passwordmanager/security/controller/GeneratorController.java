package com.passwordmanager.security.controller;

import com.passwordmanager.security.dto.*;
import com.passwordmanager.security.service.PasswordGeneratorService;
import com.passwordmanager.security.service.SecurityAuditService;
import jakarta.validation.Valid;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/generator")
@CrossOrigin(origins = "*")
@Validated
public class GeneratorController {

    private final PasswordGeneratorService generatorService;
    private final SecurityAuditService auditService;

    public GeneratorController(PasswordGeneratorService generatorService, SecurityAuditService auditService) {
        this.generatorService = generatorService;
        this.auditService = auditService;
    }

    @PostMapping("/generate")
    public List<PasswordResponse> generate(@Valid @RequestBody GeneratePasswordRequest req) {
        return generatorService.generate(req);
    }

    @GetMapping("/audit")
    public AuditResponse audit(
            @RequestHeader(value = "X-User-Id", required = false, defaultValue = "1") Long userId,
            @RequestHeader(value = "X-Master-Password", required = false) String masterPassword) {
        return auditService.generateAudit(userId, masterPassword);
    }

    @GetMapping("/audit/alerts")
    public List<AlertResponse> alerts() {
        return auditService.getRecentAlerts();
    }

    @GetMapping("/audit/passwords-analysis")
    public List<StoredPasswordAnalysisResponse> passwordAnalysis(
            @RequestHeader(value = "X-User-Id", required = false, defaultValue = "1") Long userId,
            @RequestHeader(value = "X-Master-Password", required = false) String masterPassword) {
        return auditService.analyzeStoredPasswords(userId, masterPassword);
    }

    @DeleteMapping("/audit/history")
    public String clearAuditHistory() {
        return auditService.clearAuditHistory();
    }
}
