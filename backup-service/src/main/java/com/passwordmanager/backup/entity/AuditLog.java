package com.passwordmanager.backup.entity;

import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String action;

    private String ipAddress;

    private String status;

    private Long userId;

    private LocalDateTime timestamp;

    public AuditLog() {
    }

    public AuditLog(Long id, String action, String ipAddress, String status, Long userId, LocalDateTime timestamp) {
        this.id = id;
        this.action = action;
        this.ipAddress = ipAddress;
        this.status = status;
        this.userId = userId;
        this.timestamp = timestamp;
    }

    public static AuditLogBuilder builder() {
        return new AuditLogBuilder();
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }

    public static class AuditLogBuilder {
        private Long id;
        private String action;
        private String ipAddress;
        private String status;
        private Long userId;
        private LocalDateTime timestamp;

        AuditLogBuilder() {
        }

        public AuditLogBuilder id(Long id) {
            this.id = id;
            return this;
        }

        public AuditLogBuilder action(String action) {
            this.action = action;
            return this;
        }

        public AuditLogBuilder ipAddress(String ipAddress) {
            this.ipAddress = ipAddress;
            return this;
        }

        public AuditLogBuilder status(String status) {
            this.status = status;
            return this;
        }

        public AuditLogBuilder userId(Long userId) {
            this.userId = userId;
            return this;
        }

        public AuditLogBuilder timestamp(LocalDateTime timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public AuditLog build() {
            return new AuditLog(id, action, ipAddress, status, userId, timestamp);
        }

        public String toString() {
            return "AuditLog.AuditLogBuilder(id=" + this.id + ", action=" + this.action + ", ipAddress=" + this.ipAddress + ", status=" + this.status + ", userId=" + this.userId + ", timestamp=" + this.timestamp + ")";
        }
    }
}
