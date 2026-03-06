package com.passwordmanager.security.repository;

import com.passwordmanager.security.entity.SecurityAlert;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface SecurityAlertRepository extends JpaRepository<SecurityAlert, Long> {

    List<SecurityAlert> findTop100ByOrderByCreatedAtDesc();

    boolean existsByMessageAndTypeAndCreatedAtAfter(String message, String type, LocalDateTime createdAt);
}
