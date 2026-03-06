package com.passwordmanager.backup.dto;

import java.time.LocalDateTime;

public class AuditLogResponse {

    private String action;
    private String ip;
    private String status;
    private LocalDateTime time;

    public AuditLogResponse() {
    }

    public AuditLogResponse(String action, String ip, String status, LocalDateTime time) {
        this.action = action;
        this.ip = ip;
        this.status = status;
        this.time = time;
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

    public LocalDateTime getTime() {
        return time;
    }

    public void setTime(LocalDateTime time) {
        this.time = time;
    }
}
