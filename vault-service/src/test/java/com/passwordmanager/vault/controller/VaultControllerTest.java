package com.passwordmanager.vault.controller;

import com.passwordmanager.vault.dto.PasswordEntryResponse;
import com.passwordmanager.vault.exception.GlobalExceptionHandler;
import com.passwordmanager.vault.service.VaultService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class VaultControllerTest {

    private MockMvc mockMvc;
    private VaultService vaultService;

    @BeforeEach
    void setUp() {
        vaultService = mock(VaultService.class);
        mockMvc = MockMvcBuilders.standaloneSetup(new VaultController(vaultService))
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    void getPasswordCountReturnsMap() throws Exception {
        when(vaultService.getPasswordCount(1L)).thenReturn(3L);

        mockMvc.perform(get("/api/vault/count").header("X-User-Id", 1))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.count").value(3));
    }

    @Test
    void createEntryValidatesRequest() throws Exception {
        mockMvc.perform(post("/api/vault")
                        .header("X-User-Id", 1)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"title\":\"\",\"password\":\"secret\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void exportUserVaultDelegatesToService() throws Exception {
        PasswordEntryResponse response = PasswordEntryResponse.builder().id(1L).title("Gmail").password("secret").build();
        when(vaultService.exportUserVault(5L, "master")).thenReturn(List.of(response));

        mockMvc.perform(get("/api/vault/user/5/export").header("X-Master-Password", "master"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].title").value("Gmail"));
    }

    @Test
    void searchEntriesDelegatesKeywordAndUser() throws Exception {
        PasswordEntryResponse response = PasswordEntryResponse.builder().id(4L).title("Github").build();
        when(vaultService.searchEntries(9L, "git")).thenReturn(List.of(response));

        mockMvc.perform(get("/api/vault/search")
                        .header("X-User-Id", 9)
                        .param("keyword", "git"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].title").value("Github"));

        verify(vaultService).searchEntries(9L, "git");
    }

    @Test
    void toggleFavoriteReturnsUpdatedEntry() throws Exception {
        PasswordEntryResponse response = PasswordEntryResponse.builder().id(2L).title("Mail").favorite(true).build();
        when(vaultService.toggleFavorite(3L, 2L)).thenReturn(response);

        mockMvc.perform(put("/api/vault/2/favorite").header("X-User-Id", 3))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.favorite").value(true));
    }

    @Test
    void getEntryPassesDecryptFlagAndMasterPassword() throws Exception {
        PasswordEntryResponse response = PasswordEntryResponse.builder().id(7L).title("Bank").password("decrypted").build();
        when(vaultService.getEntry(6L, 7L, true, "master")).thenReturn(response);

        mockMvc.perform(get("/api/vault/7")
                        .header("X-User-Id", 6)
                        .header("X-Master-Password", "master")
                        .param("decrypt", "true"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.password").value("decrypted"));

        verify(vaultService).getEntry(6L, 7L, true, "master");
    }
}
