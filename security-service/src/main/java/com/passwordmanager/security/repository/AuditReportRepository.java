package com.passwordmanager.security.repository;

import com.passwordmanager.security.entity.AuditReport;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AuditReportRepository extends JpaRepository<AuditReport, Long> {
}
