package com.passwordmanager.auth.repository;

import com.passwordmanager.auth.entity.VerificationCode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface VerificationCodeRepository extends JpaRepository<VerificationCode, Long> {

    Optional<VerificationCode> findByEmailAndCodeType(String email, VerificationCode.CodeType codeType);

    Optional<VerificationCode> findByEmailAndCodeAndCodeType(String email, String code, VerificationCode.CodeType codeType);

    void deleteByEmail(String email);

    void deleteByEmailAndCodeType(String email, VerificationCode.CodeType codeType);
}
