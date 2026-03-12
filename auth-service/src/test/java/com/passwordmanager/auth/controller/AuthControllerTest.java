package com.passwordmanager.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.passwordmanager.auth.dto.AuthResponse;
import com.passwordmanager.auth.entity.User;
import com.passwordmanager.auth.exception.GlobalExceptionHandler;
import com.passwordmanager.auth.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class AuthControllerTest {

    private MockMvc mockMvc;
    private AuthService authService;

    @BeforeEach
    void setUp() {
        authService = mock(AuthService.class);
        mockMvc = MockMvcBuilders.standaloneSetup(new AuthController(authService))
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    void registerReturnsAuthResponse() throws Exception {
        AuthResponse response = AuthResponse.builder().token("jwt").tokenType("Bearer").build();
        when(authService.register(any())).thenReturn(response);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(Map.of(
                                "username", "alice",
                                "email", "alice@example.com",
                                "password", "secret123"
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("jwt"));
    }

    @Test
    void getAccountRequiresAuthentication() throws Exception {
        mockMvc.perform(get("/api/auth/account"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Authentication required"));
    }

    @Test
    void getAccountSanitizesSensitiveFields() throws Exception {
        User user = User.builder()
                .username("alice")
                .password("secret")
                .masterPassword("master")
                .email("alice@example.com")
                .build();
        when(authService.getCurrentUser("alice")).thenReturn(user);

        mockMvc.perform(get("/api/auth/account")
                        .principal(new UsernamePasswordAuthenticationToken("alice", null)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.masterPassword").doesNotExist())
                .andExpect(jsonPath("$.email").value("alice@example.com"));
    }

    @Test
    void verifyMasterPasswordReturnsValidityFlag() throws Exception {
        when(authService.verifyMasterPassword("alice", "master123")).thenReturn(true);

        mockMvc.perform(post("/api/auth/master-password/verify")
                        .principal(new UsernamePasswordAuthenticationToken("alice", null))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"masterPassword\":\"master123\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true));

        verify(authService).verifyMasterPassword("alice", "master123");
    }

    @Test
    void updateTwoFactorStatusRequiresAuthentication() throws Exception {
        mockMvc.perform(put("/api/auth/2fa/status")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enabled\":true}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Authentication required"));
    }

    @Test
    void changeMasterPasswordDelegatesToService() throws Exception {
        mockMvc.perform(put("/api/auth/master-password/change")
                        .principal(new UsernamePasswordAuthenticationToken("alice", null))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "currentMasterPassword":"oldMaster",
                                  "masterPassword":"newMaster"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Master password changed successfully"));

        verify(authService).changeMasterPassword(eq("alice"), any());
    }
}
