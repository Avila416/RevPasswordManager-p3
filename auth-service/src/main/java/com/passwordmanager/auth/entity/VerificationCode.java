package com.passwordmanager.auth.entity;

import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "verification_codes")
public class VerificationCode {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String email;

    @Column(nullable = false)
    private String code;

    @Column(name = "expiry_time", nullable = false)
    private LocalDateTime expiryTime;

    @Column(name = "code_type")
    @Enumerated(EnumType.STRING)
    private CodeType codeType = CodeType.TWO_FACTOR;

    public enum CodeType {
        TWO_FACTOR, PASSWORD_RESET, MASTER_PASSWORD_RESET
    }

    public VerificationCode() {
    }

    public VerificationCode(Long id, String email, String code, LocalDateTime expiryTime, CodeType codeType) {
        this.id = id;
        this.email = email;
        this.code = code;
        this.expiryTime = expiryTime;
        this.codeType = codeType;
    }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiryTime);
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public LocalDateTime getExpiryTime() {
        return expiryTime;
    }

    public void setExpiryTime(LocalDateTime expiryTime) {
        this.expiryTime = expiryTime;
    }

    public CodeType getCodeType() {
        return codeType;
    }

    public void setCodeType(CodeType codeType) {
        this.codeType = codeType;
    }

    public static VerificationCodeBuilder builder() {
        return new VerificationCodeBuilder();
    }

    public static class VerificationCodeBuilder {
        private Long id;
        private String email;
        private String code;
        private LocalDateTime expiryTime;
        private CodeType codeType = CodeType.TWO_FACTOR;

        public VerificationCodeBuilder id(Long id) {
            this.id = id;
            return this;
        }

        public VerificationCodeBuilder email(String email) {
            this.email = email;
            return this;
        }

        public VerificationCodeBuilder code(String code) {
            this.code = code;
            return this;
        }

        public VerificationCodeBuilder expiryTime(LocalDateTime expiryTime) {
            this.expiryTime = expiryTime;
            return this;
        }

        public VerificationCodeBuilder codeType(CodeType codeType) {
            this.codeType = codeType;
            return this;
        }

        public VerificationCode build() {
            return new VerificationCode(id, email, code, expiryTime, codeType);
        }
    }
}
