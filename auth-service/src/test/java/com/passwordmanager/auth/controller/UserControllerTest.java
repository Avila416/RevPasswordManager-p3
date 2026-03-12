package com.passwordmanager.auth.controller;

import com.passwordmanager.auth.dto.UserDto;
import com.passwordmanager.auth.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class UserControllerTest {

    private MockMvc mockMvc;
    private AuthService authService;

    @BeforeEach
    void setUp() {
        authService = mock(AuthService.class);
        mockMvc = MockMvcBuilders.standaloneSetup(new UserController(authService)).build();
    }

    @Test
    void userExistsDelegatesToService() throws Exception {
        when(authService.userExists(3L)).thenReturn(true);

        mockMvc.perform(get("/api/users/exists/3"))
                .andExpect(status().isOk())
                .andExpect(content().string("true"));
    }

    @Test
    void verifyMasterPasswordReturnsBooleanPayload() throws Exception {
        when(authService.verifyMasterPasswordByUserId(5L, "master")).thenReturn(true);

        mockMvc.perform(post("/api/users/5/master-password/verify")
                        .contentType("application/json")
                        .content("{\"masterPassword\":\"master\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true));
    }

    @Test
    void getUserByIdReturnsDto() throws Exception {
        UserDto dto = UserDto.builder().id(7L).username("alice").email("alice@example.com").role("USER").build();
        when(authService.getUserById(7L)).thenReturn(dto);

        mockMvc.perform(get("/api/users/7"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("alice"));
    }
}
