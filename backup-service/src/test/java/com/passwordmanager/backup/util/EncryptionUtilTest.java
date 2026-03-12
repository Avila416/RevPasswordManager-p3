package com.passwordmanager.backup.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;

class EncryptionUtilTest {

    private EncryptionUtil encryptionUtil;

    @BeforeEach
    void setUp() {
        encryptionUtil = new EncryptionUtil();
        ReflectionTestUtils.setField(encryptionUtil, "encryptionKey", "BackupEncryptionSecretKey1234567");
    }

    @Test
    void encryptAndDecryptRoundTrip() {
        String plainText = "[{\"website\":\"example.com\",\"password\":\"secret\"}]";

        String encrypted = encryptionUtil.encrypt(plainText);

        assertTrue(encrypted.startsWith("v1:"));
        assertEquals(plainText, encryptionUtil.decrypt(encrypted));
    }

    @Test
    void encryptUsesRandomIv() {
        String plainText = "same payload";

        String first = encryptionUtil.encrypt(plainText);
        String second = encryptionUtil.encrypt(plainText);

        assertNotEquals(first, second);
    }

    @Test
    void decryptRejectsInvalidPayload() {
        RuntimeException exception = assertThrows(RuntimeException.class,
                () -> encryptionUtil.decrypt("not-base64"));

        assertEquals("Decryption failed", exception.getMessage());
    }
}
