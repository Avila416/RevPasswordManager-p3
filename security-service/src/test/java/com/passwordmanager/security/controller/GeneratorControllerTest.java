package com.passwordmanager.security.controller;

import com.passwordmanager.security.dto.AlertResponse;
import com.passwordmanager.security.dto.AuditResponse;
import com.passwordmanager.security.dto.PasswordResponse;
import com.passwordmanager.security.dto.StoredPasswordAnalysisResponse;
import com.passwordmanager.security.exception.GlobalExceptionHandler;
import com.passwordmanager.security.service.PasswordGeneratorService;
import com.passwordmanager.security.service.SecurityAuditService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.LocalDateTime;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class GeneratorControllerTest {

    private MockMvc mockMvc;
    private PasswordGeneratorService generatorService;
    private SecurityAuditService auditService;

    @BeforeEach
    void setUp() {
        generatorService = mock(PasswordGeneratorService.class);
        auditService = mock(SecurityAuditService.class);
        mockMvc = MockMvcBuilders.standaloneSetup(new GeneratorController(generatorService, auditService))
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    void generateDelegatesToService() throws Exception {
        when(generatorService.generate(any())).thenReturn(List.of(new PasswordResponse("abcDEF12!", "STRONG")));

        mockMvc.perform(post("/api/generator/generate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"length\":12,\"uppercase\":true,\"lowercase\":true,\"numbers\":true,\"specialChars\":true,\"count\":1}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].strength").value("STRONG"));
    }

    @Test
    void generateValidatesRequest() throws Exception {
        mockMvc.perform(post("/api/generator/generate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"length\":4,\"count\":0}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void clearAuditHistoryReturnsServiceMessage() throws Exception {
        when(auditService.clearAuditHistory()).thenReturn("Deleted audit history. Alerts: 1, Reports: 2");

        mockMvc.perform(delete("/api/generator/audit/history"))
                .andExpect(status().isOk())
                .andExpect(content().string("Deleted audit history. Alerts: 1, Reports: 2"));
    }

    @Test
    void auditUsesHeadersWhenProvided() throws Exception {
        AuditResponse response = AuditResponse.builder()
                .total(5)
                .weak(1)
                .reused(2)
                .old(0)
                .alertCount(1)
                .generatedAt(LocalDateTime.now())
                .build();
        when(auditService.generateAudit(4L, "master")).thenReturn(response);

        mockMvc.perform(get("/api/generator/audit")
                        .header("X-User-Id", 4)
                        .header("X-Master-Password", "master"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(5))
                .andExpect(jsonPath("$.weak").value(1))
                .andExpect(jsonPath("$.reused").value(2));

        verify(auditService).generateAudit(4L, "master");
    }

    @Test
    void passwordAnalysisReturnsServiceData() throws Exception {
        StoredPasswordAnalysisResponse response = StoredPasswordAnalysisResponse.builder()
                .entryId(11L)
                .website("Github")
                .strength("WEAK")
                .weak(true)
                .createdAt(LocalDateTime.now())
                .build();
        when(auditService.analyzeStoredPasswords(8L, "master")).thenReturn(List.of(response));

        mockMvc.perform(get("/api/generator/audit/passwords-analysis")
                        .header("X-User-Id", 8)
                        .header("X-Master-Password", "master"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].website").value("Github"))
                .andExpect(jsonPath("$[0].strength").value("WEAK"));
    }

    @Test
    void alertsReturnsRecentAlerts() throws Exception {
        AlertResponse response = AlertResponse.builder()
                .message("Weak password detected")
                .severity("HIGH")
                .type("PASSWORD")
                .createdAt(LocalDateTime.of(2026, 3, 12, 10, 0))
                .build();
        when(auditService.getRecentAlerts()).thenReturn(List.of(response));

        mockMvc.perform(get("/api/generator/audit/alerts"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].message").value("Weak password detected"))
                .andExpect(jsonPath("$[0].severity").value("HIGH"));
    }
}
