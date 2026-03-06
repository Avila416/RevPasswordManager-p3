package com.passwordmanager.security.dto;

import java.time.LocalDateTime;

public class AuditResponse {

    private int total;
    private int weak;
    private int reused;
    private int old;
    private Long reportId;
    private int alertCount;
    private LocalDateTime generatedAt;

    public AuditResponse() {
    }

    public AuditResponse(int total, int weak, int reused, int old, Long reportId, int alertCount, LocalDateTime generatedAt) {
        this.total = total;
        this.weak = weak;
        this.reused = reused;
        this.old = old;
        this.reportId = reportId;
        this.alertCount = alertCount;
        this.generatedAt = generatedAt;
    }

    public static AuditResponseBuilder builder() {
        return new AuditResponseBuilder();
    }

    public int getTotal() {
        return total;
    }

    public void setTotal(int total) {
        this.total = total;
    }

    public int getWeak() {
        return weak;
    }

    public void setWeak(int weak) {
        this.weak = weak;
    }

    public int getReused() {
        return reused;
    }

    public void setReused(int reused) {
        this.reused = reused;
    }

    public int getOld() {
        return old;
    }

    public void setOld(int old) {
        this.old = old;
    }

    public Long getReportId() {
        return reportId;
    }

    public void setReportId(Long reportId) {
        this.reportId = reportId;
    }

    public int getAlertCount() {
        return alertCount;
    }

    public void setAlertCount(int alertCount) {
        this.alertCount = alertCount;
    }

    public LocalDateTime getGeneratedAt() {
        return generatedAt;
    }

    public void setGeneratedAt(LocalDateTime generatedAt) {
        this.generatedAt = generatedAt;
    }

    public static class AuditResponseBuilder {
        private int total;
        private int weak;
        private int reused;
        private int old;
        private Long reportId;
        private int alertCount;
        private LocalDateTime generatedAt;

        AuditResponseBuilder() {
        }

        public AuditResponseBuilder total(int total) {
            this.total = total;
            return this;
        }

        public AuditResponseBuilder weak(int weak) {
            this.weak = weak;
            return this;
        }

        public AuditResponseBuilder reused(int reused) {
            this.reused = reused;
            return this;
        }

        public AuditResponseBuilder old(int old) {
            this.old = old;
            return this;
        }

        public AuditResponseBuilder reportId(Long reportId) {
            this.reportId = reportId;
            return this;
        }

        public AuditResponseBuilder alertCount(int alertCount) {
            this.alertCount = alertCount;
            return this;
        }

        public AuditResponseBuilder generatedAt(LocalDateTime generatedAt) {
            this.generatedAt = generatedAt;
            return this;
        }

        public AuditResponse build() {
            return new AuditResponse(total, weak, reused, old, reportId, alertCount, generatedAt);
        }
    }
}
