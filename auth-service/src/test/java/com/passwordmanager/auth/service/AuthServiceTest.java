package com.passwordmanager.auth.service;

import com.passwordmanager.auth.dto.AuthResponse;
import com.passwordmanager.auth.dto.LoginRequest;
import com.passwordmanager.auth.dto.MasterPasswordRequest;
import com.passwordmanager.auth.dto.RegisterRequest;
import com.passwordmanager.auth.entity.User;
import com.passwordmanager.auth.entity.VerificationCode;
import com.passwordmanager.auth.exception.BadRequestException;
import com.passwordmanager.auth.exception.UnauthorizedException;
import com.passwordmanager.auth.repository.UserRepository;
import com.passwordmanager.auth.repository.VerificationCodeRepository;
import com.passwordmanager.auth.security.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private VerificationCodeRepository verificationCodeRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtUtil jwtUtil;

    private AuthService authService;

    @BeforeEach
    void setUp() {
        authService = new AuthService(userRepository, verificationCodeRepository, passwordEncoder, jwtUtil);
    }

    @Test
    void registerCreatesUserAndReturnsToken() {
        RegisterRequest request = RegisterRequest.builder()
                .username("alice")
                .email("alice@example.com")
                .password("secret123")
                .build();
        when(passwordEncoder.encode("secret123")).thenReturn("encoded");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            user.setId(10L);
            return user;
        });
        when(jwtUtil.generateToken("alice", 10L, "USER")).thenReturn("jwt-token");

        AuthResponse response = authService.register(request);

        assertEquals("jwt-token", response.getToken());
        assertEquals("alice", response.getUser().getUsername());
        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        assertEquals("encoded", captor.getValue().getPassword());
    }

    @Test
    void registerRejectsDuplicateUsername() {
        RegisterRequest request = RegisterRequest.builder()
                .username("alice")
                .email("alice@example.com")
                .password("secret123")
                .build();
        when(userRepository.existsByUsername("alice")).thenReturn(true);

        BadRequestException exception = assertThrows(BadRequestException.class, () -> authService.register(request));

        assertEquals("Username already exists", exception.getMessage());
    }

    @Test
    void registerRejectsDuplicateEmail() {
        RegisterRequest request = RegisterRequest.builder()
                .username("alice")
                .email("alice@example.com")
                .password("secret123")
                .build();
        when(userRepository.existsByUsername("alice")).thenReturn(false);
        when(userRepository.existsByEmail("alice@example.com")).thenReturn(true);

        BadRequestException exception = assertThrows(BadRequestException.class, () -> authService.register(request));

        assertEquals("Email already exists", exception.getMessage());
    }

    @Test
    void loginReturnsTwoFactorResponseWhenEnabled() {
        LoginRequest request = LoginRequest.builder().username("alice").password("secret123").build();
        User user = User.builder()
                .id(1L)
                .username("alice")
                .email("alice@example.com")
                .password("encoded")
                .twoFactorEnabled(true)
                .role(User.Role.USER)
                .enabled(true)
                .build();
        when(userRepository.findByUsernameOrEmail("alice", "alice")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("secret123", "encoded")).thenReturn(true);

        AuthResponse response = authService.login(request);

        assertTrue(response.isRequiresTwoFactor());
        assertNull(response.getToken());
    }

    @Test
    void loginRejectsInvalidPassword() {
        LoginRequest request = LoginRequest.builder().username("alice").password("wrong").build();
        User user = User.builder()
                .username("alice")
                .password("encoded")
                .enabled(true)
                .role(User.Role.USER)
                .build();
        when(userRepository.findByUsernameOrEmail("alice", "alice")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong", "encoded")).thenReturn(false);

        UnauthorizedException exception = assertThrows(UnauthorizedException.class, () -> authService.login(request));

        assertEquals("Invalid credentials", exception.getMessage());
    }

    @Test
    void loginRejectsDisabledAccount() {
        LoginRequest request = LoginRequest.builder().username("alice").password("secret123").build();
        User user = User.builder()
                .username("alice")
                .password("encoded")
                .enabled(false)
                .role(User.Role.USER)
                .build();
        when(userRepository.findByUsernameOrEmail("alice", "alice")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("secret123", "encoded")).thenReturn(true);

        UnauthorizedException exception = assertThrows(UnauthorizedException.class, () -> authService.login(request));

        assertEquals("Account is disabled", exception.getMessage());
    }

    @Test
    void resetForgotPasswordRejectsMismatchedPasswords() {
        BadRequestException exception = assertThrows(BadRequestException.class,
                () -> authService.resetForgotPassword("a@b.com", "123456", "secret1", "secret2"));

        assertEquals("New password and confirm password must match", exception.getMessage());
    }

    @Test
    void verifyTwoFactorCodeRejectsExpiredCode() {
        VerificationCode code = VerificationCode.builder()
                .email("alice@example.com")
                .code("123456")
                .expiryTime(LocalDateTime.now().minusMinutes(1))
                .codeType(VerificationCode.CodeType.TWO_FACTOR)
                .build();
        when(verificationCodeRepository.findByEmailAndCodeAndCodeType(
                "alice@example.com", "123456", VerificationCode.CodeType.TWO_FACTOR
        )).thenReturn(Optional.of(code));

        UnauthorizedException exception = assertThrows(UnauthorizedException.class,
                () -> authService.verifyTwoFactorCode(new com.passwordmanager.auth.dto.TwoFactorRequest("alice@example.com", "123456")));

        assertEquals("Verification code has expired", exception.getMessage());
    }

    @Test
    void setupMasterPasswordRejectsWhenAlreadySet() {
        User user = User.builder().username("alice").masterPassword("existing").build();
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user));

        BadRequestException exception = assertThrows(BadRequestException.class,
                () -> authService.setupMasterPassword("alice",
                        MasterPasswordRequest.builder().masterPassword("newMaster").build()));

        assertEquals("Master password already set", exception.getMessage());
    }

    @Test
    void changeMasterPasswordRejectsWrongCurrentPassword() {
        User user = User.builder().username("alice").masterPassword("oldMaster").build();
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user));

        UnauthorizedException exception = assertThrows(UnauthorizedException.class,
                () -> authService.changeMasterPassword("alice",
                        MasterPasswordRequest.builder()
                                .currentMasterPassword("badMaster")
                                .masterPassword("newMaster")
                                .build()));

        assertEquals("Current master password is incorrect", exception.getMessage());
    }
}
