package com.passwordmanager.backup.dto;

import jakarta.validation.constraints.NotBlank;

public class AuditLogRequest {

    @NotBlank(message = "Action is required")
    private String action;

    @NotBlank(message = "IP address is required")
    private String ip;

    @NotBlank(message = "Status is required")
    private String status;

    private Long userId;

    public AuditLogRequest() {
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
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
}
