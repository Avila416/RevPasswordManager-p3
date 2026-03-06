package com.passwordmanager.vault.service;

import com.passwordmanager.vault.client.AuthServiceClient;
import com.passwordmanager.vault.dto.PasswordEntryRequest;
import com.passwordmanager.vault.dto.PasswordEntryResponse;
import com.passwordmanager.vault.entity.PasswordEntry;
import com.passwordmanager.vault.exception.BadRequestException;
import com.passwordmanager.vault.exception.ResourceNotFoundException;
import com.passwordmanager.vault.repository.PasswordEntryRepository;
import com.passwordmanager.vault.security.EncryptionUtil;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class VaultService {

    private static final Logger log = LoggerFactory.getLogger(VaultService.class);

    private final PasswordEntryRepository passwordEntryRepository;
    private final EncryptionUtil encryptionUtil;
    private final AuthServiceClient authServiceClient;

    public VaultService(PasswordEntryRepository passwordEntryRepository, EncryptionUtil encryptionUtil,
                       AuthServiceClient authServiceClient) {
        this.passwordEntryRepository = passwordEntryRepository;
        this.encryptionUtil = encryptionUtil;
        this.authServiceClient = authServiceClient;
    }

    @CircuitBreaker(name = "authService", fallbackMethod = "validateUserFallback")
    public void validateUser(Long userId) {
        Boolean exists = authServiceClient.userExists(userId);
        if (!exists) {
            throw new BadRequestException("User not found");
        }
    }

    private void validateUserFallback(Long userId, Exception e) {
        log.warn("Auth service unavailable, proceeding without user validation for userId: {}", userId);
    }

    @Transactional
    public PasswordEntryResponse createEntry(Long userId, PasswordEntryRequest request) {
        validateUser(userId);

        PasswordEntry entry = PasswordEntry.builder()
                .userId(userId)
                .title(request.getTitle())
                .username(request.getUsername())
                .encryptedPassword(encryptionUtil.encrypt(request.getPassword()))
                .website(request.getWebsite())
                .category(request.getCategory())
                .notes(request.getNotes())
                .favorite(request.isFavorite())
                .build();

        entry = passwordEntryRepository.save(entry);
        log.info("Password entry created for user: {}", userId);

        return mapToResponse(entry, false);
    }

    public List<PasswordEntryResponse> getAllEntries(Long userId) {
        return passwordEntryRepository.findByUserIdOrderByCreatedAtDesc(userId)
                .stream()
                .map(entry -> mapToResponse(entry, false))
                .collect(Collectors.toList());
    }

    public PasswordEntryResponse getEntry(Long userId, Long entryId, boolean decrypt) {
        PasswordEntry entry = passwordEntryRepository.findByIdAndUserId(entryId, userId)
                .orElseThrow(() -> new ResourceNotFoundException("Password entry not found"));
        return mapToResponse(entry, decrypt);
    }

    @Transactional
    public PasswordEntryResponse updateEntry(Long userId, Long entryId, PasswordEntryRequest request) {
        PasswordEntry entry = passwordEntryRepository.findByIdAndUserId(entryId, userId)
                .orElseThrow(() -> new ResourceNotFoundException("Password entry not found"));

        entry.setTitle(request.getTitle());
        entry.setUsername(request.getUsername());
        if (request.getPassword() != null && !request.getPassword().isEmpty()) {
            entry.setEncryptedPassword(encryptionUtil.encrypt(request.getPassword()));
        }
        entry.setWebsite(request.getWebsite());
        entry.setCategory(request.getCategory());
        entry.setNotes(request.getNotes());
        entry.setFavorite(request.isFavorite());

        entry = passwordEntryRepository.save(entry);
        log.info("Password entry updated: {}", entryId);

        return mapToResponse(entry, false);
    }

    @Transactional
    public void deleteEntry(Long userId, Long entryId) {
        PasswordEntry entry = passwordEntryRepository.findByIdAndUserId(entryId, userId)
                .orElseThrow(() -> new ResourceNotFoundException("Password entry not found"));
        passwordEntryRepository.delete(entry);
        log.info("Password entry deleted: {}", entryId);
    }

    @Transactional
    public PasswordEntryResponse toggleFavorite(Long userId, Long entryId) {
        PasswordEntry entry = passwordEntryRepository.findByIdAndUserId(entryId, userId)
                .orElseThrow(() -> new ResourceNotFoundException("Password entry not found"));
        entry.setFavorite(!entry.isFavorite());
        entry = passwordEntryRepository.save(entry);
        return mapToResponse(entry, false);
    }

    public List<PasswordEntryResponse> getFavorites(Long userId) {
        return passwordEntryRepository.findByUserIdAndFavoriteTrue(userId)
                .stream()
                .map(entry -> mapToResponse(entry, false))
                .collect(Collectors.toList());
    }

    public List<PasswordEntryResponse> searchEntries(Long userId, String keyword) {
        return passwordEntryRepository.searchByKeyword(userId, keyword)
                .stream()
                .map(entry -> mapToResponse(entry, false))
                .collect(Collectors.toList());
    }

    public List<PasswordEntryResponse> getByDomain(Long userId, String domain) {
        return passwordEntryRepository.findByDomain(userId, domain)
                .stream()
                .map(entry -> mapToResponse(entry, false))
                .collect(Collectors.toList());
    }

    public long getPasswordCount(Long userId) {
        return passwordEntryRepository.countByUserId(userId);
    }

    public List<PasswordEntryResponse> exportUserVault(Long userId) {
        return passwordEntryRepository.findByUserIdOrderByCreatedAtDesc(userId)
                .stream()
                .map(entry -> mapToResponse(entry, true))
                .collect(Collectors.toList());
    }

    private PasswordEntryResponse mapToResponse(PasswordEntry entry, boolean decrypt) {
        return PasswordEntryResponse.builder()
                .id(entry.getId())
                .title(entry.getTitle())
                .username(entry.getUsername())
                .password(decrypt ? encryptionUtil.decrypt(entry.getEncryptedPassword()) : "********")
                .website(entry.getWebsite())
                .category(entry.getCategory())
                .notes(entry.getNotes())
                .favorite(entry.isFavorite())
                .createdAt(entry.getCreatedAt())
                .updatedAt(entry.getUpdatedAt())
                .build();
    }
}
