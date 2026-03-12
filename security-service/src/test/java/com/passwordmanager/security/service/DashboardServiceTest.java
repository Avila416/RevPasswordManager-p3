package com.passwordmanager.security.service;

import com.passwordmanager.security.client.VaultServiceClient;
import com.passwordmanager.security.dto.DashboardResponse;
import com.passwordmanager.security.dto.PasswordEntryDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DashboardServiceTest {

    @Mock
    private VaultServiceClient vaultServiceClient;

    private DashboardService dashboardService;

    @BeforeEach
    void setUp() {
        dashboardService = new DashboardService(vaultServiceClient, new PasswordStrengthService());
    }

    @Test
    void getDashboardReturnsEmptyWhenMasterPasswordMissing() {
        DashboardResponse response = dashboardService.getDashboard(1L, " ");

        assertEquals(0, response.getTotalPasswords());
        assertEquals(0, response.getWeakPasswords());
    }

    @Test
    void getDashboardCountsTotalsRecentAndWeakPasswords() {
        PasswordEntryDto weakRecent = new PasswordEntryDto();
        weakRecent.setEncryptedPassword("short");
        weakRecent.setCreatedAt(LocalDateTime.now().minusDays(1));
        PasswordEntryDto strongOld = new PasswordEntryDto();
        strongOld.setEncryptedPassword("Longer#Pass123");
        strongOld.setCreatedAt(LocalDateTime.now().minusDays(30));
        when(vaultServiceClient.getUserPasswords(1L, "master")).thenReturn(List.of(weakRecent, strongOld));

        DashboardResponse response = dashboardService.getDashboard(1L, "master");

        assertEquals(2, response.getTotalPasswords());
        assertEquals(1, response.getWeakPasswords());
        assertEquals(1, response.getRecentPasswords());
    }

    @Test
    void getDashboardTreatsNullPasswordAsWeak() {
        PasswordEntryDto entry = new PasswordEntryDto();
        entry.setEncryptedPassword(null);
        entry.setCreatedAt(LocalDateTime.now());
        when(vaultServiceClient.getUserPasswords(2L, "master")).thenReturn(List.of(entry));

        DashboardResponse response = dashboardService.getDashboard(2L, "master");

        assertEquals(1, response.getTotalPasswords());
        assertEquals(1, response.getWeakPasswords());
    }

    @Test
    void getDashboardFallbackReturnsZeros() {
        DashboardResponse response = dashboardService.getDashboardFallback(1L, "master", new RuntimeException("down"));

        assertEquals(0, response.getTotalPasswords());
        assertEquals(0, response.getWeakPasswords());
        assertEquals(0, response.getRecentPasswords());
    }
}
