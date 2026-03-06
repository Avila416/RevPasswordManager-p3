package com.passwordmanager.vault.controller;

import com.passwordmanager.vault.dto.PasswordEntryRequest;
import com.passwordmanager.vault.dto.PasswordEntryResponse;
import com.passwordmanager.vault.service.VaultService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/vault")
public class VaultController {

    private final VaultService vaultService;

    public VaultController(VaultService vaultService) {
        this.vaultService = vaultService;
    }

    @PostMapping
    public ResponseEntity<PasswordEntryResponse> createEntry(
            @RequestHeader("X-User-Id") Long userId,
            @Valid @RequestBody PasswordEntryRequest request) {
        return ResponseEntity.ok(vaultService.createEntry(userId, request));
    }

    @GetMapping
    public ResponseEntity<List<PasswordEntryResponse>> getAllEntries(
            @RequestHeader("X-User-Id") Long userId) {
        return ResponseEntity.ok(vaultService.getAllEntries(userId));
    }

    @GetMapping("/{id}")
    public ResponseEntity<PasswordEntryResponse> getEntry(
            @RequestHeader("X-User-Id") Long userId,
            @PathVariable Long id,
            @RequestParam(defaultValue = "false") boolean decrypt) {
        return ResponseEntity.ok(vaultService.getEntry(userId, id, decrypt));
    }

    @PutMapping("/{id}")
    public ResponseEntity<PasswordEntryResponse> updateEntry(
            @RequestHeader("X-User-Id") Long userId,
            @PathVariable Long id,
            @Valid @RequestBody PasswordEntryRequest request) {
        return ResponseEntity.ok(vaultService.updateEntry(userId, id, request));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Map<String, String>> deleteEntry(
            @RequestHeader("X-User-Id") Long userId,
            @PathVariable Long id) {
        vaultService.deleteEntry(userId, id);
        return ResponseEntity.ok(Map.of("message", "Password entry deleted successfully"));
    }

    @PutMapping("/{id}/favorite")
    public ResponseEntity<PasswordEntryResponse> toggleFavorite(
            @RequestHeader("X-User-Id") Long userId,
            @PathVariable Long id) {
        return ResponseEntity.ok(vaultService.toggleFavorite(userId, id));
    }

    @GetMapping("/favorites")
    public ResponseEntity<List<PasswordEntryResponse>> getFavorites(
            @RequestHeader("X-User-Id") Long userId) {
        return ResponseEntity.ok(vaultService.getFavorites(userId));
    }

    @GetMapping("/search")
    public ResponseEntity<List<PasswordEntryResponse>> searchEntries(
            @RequestHeader("X-User-Id") Long userId,
            @RequestParam String keyword) {
        return ResponseEntity.ok(vaultService.searchEntries(userId, keyword));
    }

    @GetMapping("/by-domain")
    public ResponseEntity<List<PasswordEntryResponse>> getByDomain(
            @RequestHeader("X-User-Id") Long userId,
            @RequestParam String domain) {
        return ResponseEntity.ok(vaultService.getByDomain(userId, domain));
    }

    @GetMapping("/count")
    public ResponseEntity<Map<String, Long>> getPasswordCount(
            @RequestHeader("X-User-Id") Long userId) {
        return ResponseEntity.ok(Map.of("count", vaultService.getPasswordCount(userId)));
    }

    @GetMapping("/user/{userId}/export")
    public ResponseEntity<List<PasswordEntryResponse>> exportUserVault(@PathVariable Long userId) {
        return ResponseEntity.ok(vaultService.exportUserVault(userId));
    }
}
