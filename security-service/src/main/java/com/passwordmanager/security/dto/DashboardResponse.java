package com.passwordmanager.security.dto;

import java.util.Map;

public class DashboardResponse {

    private long totalPasswords;
    private long weakPasswords;
    private long recentPasswords;
    private Map<String, Long> actionStats;

    public DashboardResponse() {
    }

    public DashboardResponse(long totalPasswords, long weakPasswords, long recentPasswords, Map<String, Long> actionStats) {
        this.totalPasswords = totalPasswords;
        this.weakPasswords = weakPasswords;
        this.recentPasswords = recentPasswords;
        this.actionStats = actionStats;
    }

    public long getTotalPasswords() {
        return totalPasswords;
    }

    public void setTotalPasswords(long totalPasswords) {
        this.totalPasswords = totalPasswords;
    }

    public long getWeakPasswords() {
        return weakPasswords;
    }

    public void setWeakPasswords(long weakPasswords) {
        this.weakPasswords = weakPasswords;
    }

    public long getRecentPasswords() {
        return recentPasswords;
    }

    public void setRecentPasswords(long recentPasswords) {
        this.recentPasswords = recentPasswords;
    }

    public Map<String, Long> getActionStats() {
        return actionStats;
    }

    public void setActionStats(Map<String, Long> actionStats) {
        this.actionStats = actionStats;
    }
}
