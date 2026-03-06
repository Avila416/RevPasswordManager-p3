package com.passwordmanager.backup.repository;

import com.passwordmanager.backup.entity.BackupFile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface BackupFileRepository extends JpaRepository<BackupFile, Long> {

    List<BackupFile> findByUserIdOrderByCreatedAtDesc(Long userId);

    Optional<BackupFile> findTopByUserIdOrderByCreatedAtDesc(Long userId);
}
