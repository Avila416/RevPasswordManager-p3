package com.passwordmanager.security.dto;

import java.time.LocalDateTime;

public class AlertResponse {

    private Long id;
    private String message;
    private String severity;
    private String type;
    private LocalDateTime createdAt;

    public AlertResponse() {
    }

    public AlertResponse(Long id, String message, String severity, String type, LocalDateTime createdAt) {
        this.id = id;
        this.message = message;
        this.severity = severity;
        this.type = type;
        this.createdAt = createdAt;
    }

    public static AlertResponseBuilder builder() {
        return new AlertResponseBuilder();
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

    public static class AlertResponseBuilder {
        private Long id;
        private String message;
        private String severity;
        private String type;
        private LocalDateTime createdAt;

        AlertResponseBuilder() {
        }

        public AlertResponseBuilder id(Long id) {
            this.id = id;
            return this;
        }

        public AlertResponseBuilder message(String message) {
            this.message = message;
            return this;
        }

        public AlertResponseBuilder severity(String severity) {
            this.severity = severity;
            return this;
        }

        public AlertResponseBuilder type(String type) {
            this.type = type;
            return this;
        }

        public AlertResponseBuilder createdAt(LocalDateTime createdAt) {
            this.createdAt = createdAt;
            return this;
        }

        public AlertResponse build() {
            return new AlertResponse(id, message, severity, type, createdAt);
        }
    }
}
