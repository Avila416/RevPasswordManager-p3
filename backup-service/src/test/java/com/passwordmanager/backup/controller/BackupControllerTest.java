package com.passwordmanager.backup.controller;

import com.passwordmanager.backup.exception.GlobalExceptionHandler;
import com.passwordmanager.backup.service.BackupService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(BackupController.class)
@Import(GlobalExceptionHandler.class)
class BackupControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private BackupService backupService;

    @Test
    void exportDelegatesHeadersToService() throws Exception {
        when(backupService.exportBackup(7L, "master")).thenReturn("checksum.payload");

        mockMvc.perform(get("/api/backup/export")
                        .header("X-User-Id", 7)
                        .header("X-Master-Password", "master"))
                .andExpect(status().isOk())
                .andExpect(content().string("checksum.payload"));

        verify(backupService).exportBackup(7L, "master");
    }

    @Test
    void restoreAcceptsNestedFileContentValue() throws Exception {
        when(backupService.restoreBackup("payload-data", 5L)).thenReturn(Map.of("message", "ok"));

        mockMvc.perform(post("/api/backup/restore")
                        .header("X-User-Id", 5)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fileContent\":{\"value\":\"payload-data\"}}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("ok"));

        verify(backupService).restoreBackup("payload-data", 5L);
    }

    @Test
    void validateRejectsMissingBackupContent() throws Exception {
        mockMvc.perform(patch("/api/backup/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Backup content is required"));
    }

    @Test
    void restoreAcceptsRawTextPayload() throws Exception {
        when(backupService.restoreBackup("checksum.payload", 1L)).thenReturn(Map.of("message", "restored"));

        mockMvc.perform(post("/api/backup/restore")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("\"checksum.payload\""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("restored"));

        verify(backupService).restoreBackup("checksum.payload", 1L);
    }

    @Test
    void updateRejectsOversizedBackupContent() throws Exception {
        String largeContent = "a".repeat(2_000_001);

        mockMvc.perform(put("/api/backup/update")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fileContent\":\"" + largeContent + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Backup content is too large"));
    }

    @Test
    void latestBackupUsesDefaultUserHeaderWhenMissing() throws Exception {
        when(backupService.latestBackupInfo(1L)).thenReturn(Map.of("exists", false, "fileName", "", "createdAt", ""));

        mockMvc.perform(get("/api/backup/latest"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.exists").value(false));

        verify(backupService).latestBackupInfo(1L);
    }
}
