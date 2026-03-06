package com.passwordmanager.auth.service;

import com.passwordmanager.auth.dto.*;
import com.passwordmanager.auth.entity.User;
import com.passwordmanager.auth.entity.VerificationCode;
import com.passwordmanager.auth.exception.BadRequestException;
import com.passwordmanager.auth.exception.ResourceNotFoundException;
import com.passwordmanager.auth.exception.UnauthorizedException;
import com.passwordmanager.auth.repository.UserRepository;
import com.passwordmanager.auth.repository.VerificationCodeRepository;
import com.passwordmanager.auth.security.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Random;

@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final VerificationCodeRepository verificationCodeRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public AuthService(UserRepository userRepository, VerificationCodeRepository verificationCodeRepository,
                       PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.verificationCodeRepository = verificationCodeRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new BadRequestException("Username already exists");
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new BadRequestException("Email already exists");
        }

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .phone(request.getPhone())
                .securityQuestion(request.getSecurityQuestion())
                .securityAnswer(request.getSecurityAnswer())
                .build();

        user = userRepository.save(user);
        log.info("User registered: {}", user.getUsername());

        String token = jwtUtil.generateToken(user.getUsername(), user.getId(), user.getRole().name());

        return AuthResponse.builder()
                .token(token)
                .tokenType("Bearer")
                .user(mapToUserDto(user))
                .build();
    }

    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByUsernameOrEmail(request.getUsername(), request.getUsername())
                .orElseThrow(() -> new UnauthorizedException("Invalid credentials"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new UnauthorizedException("Invalid credentials");
        }

        if (!user.isEnabled()) {
            throw new UnauthorizedException("Account is disabled");
        }

        if (user.isTwoFactorEnabled()) {
            return AuthResponse.builder()
                    .requiresTwoFactor(true)
                    .user(mapToUserDto(user))
                    .build();
        }

        String token = jwtUtil.generateToken(user.getUsername(), user.getId(), user.getRole().name());
        log.info("User logged in: {}", user.getUsername());

        return AuthResponse.builder()
                .token(token)
                .tokenType("Bearer")
                .user(mapToUserDto(user))
                .build();
    }

    public User getCurrentUser(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    }

    public UserDto getUserById(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        return UserDto.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .role(user.getRole().name())
                .build();
    }

    public boolean userExists(Long id) {
        return userRepository.existsById(id);
    }

    @Transactional
    public void setupMasterPassword(String username, MasterPasswordRequest request) {
        User user = getCurrentUser(username);
        if (user.getMasterPassword() != null) {
            throw new BadRequestException("Master password already set");
        }
        user.setMasterPassword(request.getMasterPassword());
        userRepository.save(user);
        log.info("Master password set for user: {}", username);
    }

    @Transactional
    public void changeMasterPassword(String username, MasterPasswordRequest request) {
        User user = getCurrentUser(username);
        if (user.getMasterPassword() == null) {
            throw new BadRequestException("Master password not set");
        }
        if (!user.getMasterPassword().equals(request.getCurrentMasterPassword())) {
            throw new UnauthorizedException("Current master password is incorrect");
        }
        user.setMasterPassword(request.getMasterPassword());
        userRepository.save(user);
        log.info("Master password changed for user: {}", username);
    }

    public boolean verifyMasterPassword(String username, String masterPassword) {
        User user = getCurrentUser(username);
        return user.getMasterPassword() != null && user.getMasterPassword().equals(masterPassword);
    }

    @Transactional
    public void requestTwoFactorCode(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        String code = generateOtp();

        verificationCodeRepository.deleteByEmailAndCodeType(email, VerificationCode.CodeType.TWO_FACTOR);

        VerificationCode verificationCode = VerificationCode.builder()
                .email(email)
                .code(code)
                .expiryTime(LocalDateTime.now().plusMinutes(10))
                .codeType(VerificationCode.CodeType.TWO_FACTOR)
                .build();

        verificationCodeRepository.save(verificationCode);
        log.info("2FA code generated for: {} - Code: {}", email, code);
    }

    @Transactional
    public AuthResponse verifyTwoFactorCode(TwoFactorRequest request) {
        VerificationCode verificationCode = verificationCodeRepository
                .findByEmailAndCodeAndCodeType(request.getEmail(), request.getCode(), VerificationCode.CodeType.TWO_FACTOR)
                .orElseThrow(() -> new UnauthorizedException("Invalid verification code"));

        if (verificationCode.isExpired()) {
            throw new UnauthorizedException("Verification code has expired");
        }

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        verificationCodeRepository.delete(verificationCode);

        String token = jwtUtil.generateToken(user.getUsername(), user.getId(), user.getRole().name());

        return AuthResponse.builder()
                .token(token)
                .tokenType("Bearer")
                .user(mapToUserDto(user))
                .build();
    }

    @Transactional
    public void updateTwoFactorStatus(String username, boolean enabled) {
        User user = getCurrentUser(username);
        user.setTwoFactorEnabled(enabled);
        userRepository.save(user);
        log.info("2FA {} for user: {}", enabled ? "enabled" : "disabled", username);
    }

    private String generateOtp() {
        Random random = new Random();
        return String.format("%06d", random.nextInt(1000000));
    }

    private AuthResponse.UserDto mapToUserDto(User user) {
        return AuthResponse.UserDto.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .role(user.getRole().name())
                .hasMasterPassword(user.getMasterPassword() != null)
                .twoFactorEnabled(user.isTwoFactorEnabled())
                .build();
    }
}
