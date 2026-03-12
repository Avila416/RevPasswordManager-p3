package com.passwordmanager.backup.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class FileUtilTest {

    private final FileUtil fileUtil = new FileUtil();

    @Test
    void validateReturnsTrueForNonBlankContent() {
        assertTrue(fileUtil.validate("payload"));
    }

    @Test
    void validateReturnsFalseForBlankContent() {
        assertFalse(fileUtil.validate("   "));
        assertFalse(fileUtil.validate(null));
    }
}
