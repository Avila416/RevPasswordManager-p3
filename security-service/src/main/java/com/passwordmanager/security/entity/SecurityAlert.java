package com.passwordmanager.security.entity;

import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
public class SecurityAlert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String message;
    private String severity; // LOW, MEDIUM, HIGH
    private String type; // WEAK, REUSED, OLD

    private LocalDateTime createdAt;

    public SecurityAlert() {
    }

    public SecurityAlert(Long id, String message, String severity, String type, LocalDateTime createdAt) {
        this.id = id;
        this.message = message;
        this.severity = severity;
        this.type = type;
        this.createdAt = createdAt;
    }

    public static SecurityAlertBuilder builder() {
        return new SecurityAlertBuilder();
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public static class SecurityAlertBuilder {
        private Long id;
        private String message;
        private String severity;
        private String type;
        private LocalDateTime createdAt;

        SecurityAlertBuilder() {
        }

        public SecurityAlertBuilder id(Long id) {
            this.id = id;
            return this;
        }

        public SecurityAlertBuilder message(String message) {
            this.message = message;
            return this;
        }

        public SecurityAlertBuilder severity(String severity) {
            this.severity = severity;
            return this;
        }

        public SecurityAlertBuilder type(String type) {
            this.type = type;
            return this;
        }

        public SecurityAlertBuilder createdAt(LocalDateTime createdAt) {
            this.createdAt = createdAt;
            return this;
        }

        public SecurityAlert build() {
            return new SecurityAlert(id, message, severity, type, createdAt);
        }
    }
}
