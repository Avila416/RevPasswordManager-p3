package com.passwordmanager.backup.controller;

import com.passwordmanager.backup.dto.AuditLogResponse;
import com.passwordmanager.backup.exception.GlobalExceptionHandler;
import com.passwordmanager.backup.service.AuditLogService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuditController.class)
@Import(GlobalExceptionHandler.class)
class AuditControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuditLogService auditLogService;

    @Test
    void logsFiltersByNormalizedQueryParameters() throws Exception {
        when(auditLogService.getLogs()).thenReturn(List.of(
                new AuditLogResponse("LOGIN", "127.0.0.1", "SUCCESS", LocalDateTime.of(2026, 3, 11, 10, 0)),
                new AuditLogResponse("DELETE", "10.0.0.5", "FAILED", LocalDateTime.of(2026, 3, 11, 11, 0))
        ));

        mockMvc.perform(get("/api/audit")
                        .param("action", " log ")
                        .param("status", " success "))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].action").value("LOGIN"));
    }

    @Test
    void logActionValidatesRequestBody() throws Exception {
        mockMvc.perform(post("/api/audit/log")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"action\":\"\",\"ip\":\"127.0.0.1\",\"status\":\"SUCCESS\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("action: Action is required"));
    }

    @Test
    void logsRejectOverlongQueryParams() throws Exception {
        mockMvc.perform(get("/api/audit")
                        .param("status", "x".repeat(31)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Status filter is too long"));
    }

    @Test //
    void logActionDelegatesToService() throws Exception {
        mockMvc.perform(post("/api/audit/log")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"action\":\"LOGIN\",\"ip\":\"127.0.0.1\",\"status\":\"SUCCESS\",\"userId\":1}"))
                .andExpect(status().isOk());

        verify(auditLogService).log(any());
    }
}
