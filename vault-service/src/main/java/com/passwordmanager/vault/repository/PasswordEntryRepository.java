package com.passwordmanager.vault.repository;

import com.passwordmanager.vault.entity.PasswordEntry;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface PasswordEntryRepository extends JpaRepository<PasswordEntry, Long> {

    List<PasswordEntry> findByUserIdOrderByCreatedAtDesc(Long userId);

    List<PasswordEntry> findByUserIdAndFavoriteTrue(Long userId);

    List<PasswordEntry> findByUserIdAndCategory(Long userId, String category);

    @Query("SELECT p FROM PasswordEntry p WHERE p.userId = :userId AND " +
           "(LOWER(p.title) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
           "LOWER(p.website) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
           "LOWER(p.username) LIKE LOWER(CONCAT('%', :keyword, '%')))")
    List<PasswordEntry> searchByKeyword(Long userId, String keyword);

    @Query("SELECT p FROM PasswordEntry p WHERE p.userId = :userId AND " +
           "LOWER(p.website) LIKE LOWER(CONCAT('%', :domain, '%'))")
    List<PasswordEntry> findByDomain(Long userId, String domain);

    Optional<PasswordEntry> findByIdAndUserId(Long id, Long userId);

    long countByUserId(Long userId);

    void deleteByIdAndUserId(Long id, Long userId);
}
