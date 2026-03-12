package com.passwordmanager.vault.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;

class EncryptionUtilTest {

    private EncryptionUtil encryptionUtil;

    @BeforeEach
    void setUp() {
        encryptionUtil = new EncryptionUtil();
        ReflectionTestUtils.setField(encryptionUtil, "secretKey", "BackupEncryptionSecretKey1234567");
    }

    @Test
    void encryptAndDecryptRoundTrip() {
        String encrypted = encryptionUtil.encrypt("secret");

        assertNotEquals("secret", encrypted);
        assertEquals("secret", encryptionUtil.decrypt(encrypted));
    }

    @Test
    void decryptRejectsBadPayload() {
        RuntimeException exception = assertThrows(RuntimeException.class, () -> encryptionUtil.decrypt("bad"));

        assertEquals("Decryption failed", exception.getMessage());
    }
}
