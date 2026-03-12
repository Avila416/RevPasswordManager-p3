package com.passwordmanager.vault.service;

import com.passwordmanager.vault.client.AuthServiceClient;
import com.passwordmanager.vault.dto.PasswordEntryRequest;
import com.passwordmanager.vault.dto.PasswordEntryResponse;
import com.passwordmanager.vault.entity.PasswordEntry;
import com.passwordmanager.vault.exception.BadRequestException;
import com.passwordmanager.vault.repository.PasswordEntryRepository;
import com.passwordmanager.vault.security.EncryptionUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class VaultServiceTest {

    @Mock
    private PasswordEntryRepository passwordEntryRepository;

    @Mock
    private AuthServiceClient authServiceClient;

    private VaultService vaultService;

    @BeforeEach
    void setUp() {
        EncryptionUtil encryptionUtil = new EncryptionUtil();
        ReflectionTestUtils.setField(encryptionUtil, "secretKey", "BackupEncryptionSecretKey1234567");
        vaultService = new VaultService(passwordEntryRepository, encryptionUtil, authServiceClient);
    }

    @Test
    void createEntryEncryptsPassword() {
        when(authServiceClient.userExists(1L)).thenReturn(true);
        when(passwordEntryRepository.save(any())).thenAnswer(invocation -> {
            PasswordEntry entry = invocation.getArgument(0);
            entry.setId(2L);
            entry.setCreatedAt(LocalDateTime.now());
            return entry;
        });

        PasswordEntryResponse response = vaultService.createEntry(1L,
                PasswordEntryRequest.builder().title("Gmail").password("secret123").website("gmail.com").build());

        assertEquals("********", response.getPassword());
        verify(passwordEntryRepository).save(any());
    }

    @Test
    void createEntryRejectsBlankPassword() {
        when(authServiceClient.userExists(1L)).thenReturn(true);

        BadRequestException exception = assertThrows(BadRequestException.class,
                () -> vaultService.createEntry(1L,
                        PasswordEntryRequest.builder().title("Gmail").password(" ").build()));

        assertEquals("Password is required", exception.getMessage());
    }

    @Test
    void createEntryRejectsUnknownUser() {
        when(authServiceClient.userExists(99L)).thenReturn(false);

        BadRequestException exception = assertThrows(BadRequestException.class,
                () -> vaultService.createEntry(99L,
                        PasswordEntryRequest.builder().title("Gmail").password("secret123").build()));

        assertEquals("User not found", exception.getMessage());
    }

    @Test
    void deleteEntryRequiresMasterPassword() {
        BadRequestException exception = assertThrows(BadRequestException.class,
                () -> vaultService.deleteEntry(1L, 2L, " "));

        assertEquals("Master password is required", exception.getMessage());
    }

    @Test
    void exportUserVaultDecryptsStoredPasswords() {
        when(authServiceClient.verifyMasterPassword(eq(1L), any())).thenReturn(Map.of("valid", true));
        EncryptionUtil encryptionUtil = new EncryptionUtil();
        ReflectionTestUtils.setField(encryptionUtil, "secretKey", "BackupEncryptionSecretKey1234567");
        String encrypted = encryptionUtil.encrypt("secret123");
        PasswordEntry entry = PasswordEntry.builder()
                .id(1L)
                .userId(1L)
                .title("Gmail")
                .encryptedPassword(encrypted)
                .createdAt(LocalDateTime.now())
                .build();
        when(passwordEntryRepository.findByUserIdOrderByCreatedAtDesc(1L)).thenReturn(List.of(entry));

        List<PasswordEntryResponse> result = vaultService.exportUserVault(1L, "master");

        assertEquals(1, result.size());
        assertEquals("secret123", result.get(0).getPassword());
    }

    @Test
    void getEntryRejectsInvalidMasterPasswordWhenDecrypting() {
        PasswordEntry entry = PasswordEntry.builder()
                .id(1L)
                .userId(1L)
                .title("Gmail")
                .encryptedPassword("encrypted")
                .build();
        when(passwordEntryRepository.findByIdAndUserId(1L, 1L)).thenReturn(Optional.of(entry));
        when(authServiceClient.verifyMasterPassword(eq(1L), any())).thenReturn(Map.of("valid", false));

        BadRequestException exception = assertThrows(BadRequestException.class,
                () -> vaultService.getEntry(1L, 1L, true, "wrong"));

        assertEquals("Invalid master password", exception.getMessage());
    }

    @Test
    void updateEntryKeepsExistingPasswordWhenBlankPasswordProvided() {
        EncryptionUtil encryptionUtil = new EncryptionUtil();
        ReflectionTestUtils.setField(encryptionUtil, "secretKey", "BackupEncryptionSecretKey1234567");
        String encrypted = encryptionUtil.encrypt("secret123");
        PasswordEntry entry = PasswordEntry.builder()
                .id(6L)
                .userId(3L)
                .title("Mail")
                .encryptedPassword(encrypted)
                .build();
        when(passwordEntryRepository.findByIdAndUserId(6L, 3L)).thenReturn(Optional.of(entry));
        when(passwordEntryRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        PasswordEntryResponse response = vaultService.updateEntry(3L, 6L,
                PasswordEntryRequest.builder().title("Mail Updated").password("").build());

        assertEquals("********", response.getPassword());
        assertEquals(encrypted, entry.getEncryptedPassword());
    }

    @Test
    void toggleFavoriteFlipsFavoriteFlag() {
        PasswordEntry entry = PasswordEntry.builder().id(10L).userId(2L).title("Github").favorite(false).build();
        when(passwordEntryRepository.findByIdAndUserId(10L, 2L)).thenReturn(Optional.of(entry));
        when(passwordEntryRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        PasswordEntryResponse response = vaultService.toggleFavorite(2L, 10L);

        assertTrue(response.isFavorite());
    }

    @Test
    void restoreUserVaultSkipsIncompleteEntries() {
        when(passwordEntryRepository.countByUserId(5L)).thenReturn(1L);

        long count = vaultService.restoreUserVault(5L, List.of(
                PasswordEntryRequest.builder().title(" ").password("secret").build(),
                PasswordEntryRequest.builder().title("Github").password("secret").build()
        ));

        assertEquals(1L, count);
        verify(passwordEntryRepository).deleteByUserId(5L);
        verify(passwordEntryRepository, times(1)).save(any());
    }

    @Test
    void restoreUserVaultRejectsNullEntries() {
        BadRequestException exception = assertThrows(BadRequestException.class,
                () -> vaultService.restoreUserVault(5L, null));

        assertEquals("Restore entries are required", exception.getMessage());
    }
}
