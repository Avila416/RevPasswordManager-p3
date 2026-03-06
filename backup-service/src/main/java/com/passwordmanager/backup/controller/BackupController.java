package com.passwordmanager.backup.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.passwordmanager.backup.service.BackupService;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/backup")
@Validated
@CrossOrigin(origins = "*")
public class BackupController {

    private final BackupService service;

    public BackupController(BackupService service) {
        this.service = service;
    }

    @GetMapping("/export")
    public String export(@RequestHeader(value = "X-User-Id", required = false, defaultValue = "1") Long userId) {
        return service.exportBackup(userId);
    }

    @PostMapping("/restore")
    public Map<String, Object> restore(
            @RequestBody JsonNode req,
            @RequestHeader(value = "X-User-Id", required = false, defaultValue = "1") Long userId) {
        return service.restoreBackup(extractFileContent(req), userId);
    }

    @PutMapping("/update")
    public Map<String, Object> updateBackup(
            @RequestBody JsonNode req,
            @RequestHeader(value = "X-User-Id", required = false, defaultValue = "1") Long userId) {
        return service.updateBackup(extractFileContent(req), userId);
    }

    @PatchMapping("/validate")
    public Map<String, Object> validateBackup(
            @RequestBody JsonNode req,
            @RequestHeader(value = "X-User-Id", required = false, defaultValue = "1") Long userId) {
        return service.validateBackup(extractFileContent(req), userId);
    }

    @DeleteMapping("/delete")
    public String deleteBackup(@RequestHeader(value = "X-User-Id", required = false, defaultValue = "1") Long userId) {
        return service.deleteBackup(userId);
    }

    @GetMapping("/latest")
    public Map<String, Object> latestBackup(
            @RequestHeader(value = "X-User-Id", required = false, defaultValue = "1") Long userId) {
        return service.latestBackupInfo(userId);
    }

    private String extractFileContent(JsonNode req) {
        if (req == null || req.isNull()) {
            throw new IllegalArgumentException("Backup content is required");
        }

        String content = null;
        if (req.isTextual()) {
            content = req.asText();
        } else if (req.has("fileContent")) {
            JsonNode fileContent = req.get("fileContent");
            if (fileContent != null && fileContent.isTextual()) {
                content = fileContent.asText();
            } else if (fileContent != null && fileContent.has("value") && fileContent.get("value").isTextual()) {
                content = fileContent.get("value").asText();
            }
        }

        if (!StringUtils.hasText(content)) {
            throw new IllegalArgumentException("Backup content is required");
        }

        if (content.length() > 2_000_000) {
            throw new IllegalArgumentException("Backup content is too large");
        }

        return content;
    }
}
