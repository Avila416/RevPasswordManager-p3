package com.passwordmanager.security.service;

import com.passwordmanager.security.dto.GeneratePasswordRequest;
import com.passwordmanager.security.dto.PasswordResponse;
import com.passwordmanager.security.exception.InvalidInputException;
import com.passwordmanager.security.exception.OperationFailedException;
import com.passwordmanager.security.util.PasswordUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class PasswordGeneratorServiceTest {

    private PasswordGeneratorService service;

    @BeforeEach
    void setUp() {
        service = new PasswordGeneratorService(new PasswordUtil(), new PasswordStrengthService());
    }

    @Test
    void generateReturnsRequestedCount() {
        GeneratePasswordRequest request = new GeneratePasswordRequest();
        request.setLength(12);
        request.setUppercase(true);
        request.setLowercase(true);
        request.setNumbers(true);
        request.setSpecialChars(true);
        request.setCount(3);

        List<PasswordResponse> result = service.generate(request);

        assertEquals(3, result.size());
        assertTrue(result.stream().allMatch(response -> response.getPassword().length() == 12));
    }

    @Test
    void generateRejectsMissingCharacterTypes() {
        GeneratePasswordRequest request = new GeneratePasswordRequest();
        request.setLength(12);
        request.setCount(1);

        InvalidInputException exception = assertThrows(InvalidInputException.class, () -> service.generate(request));

        assertEquals("Select at least one character type", exception.getMessage());
    }

    @Test
    void generateRejectsInvalidLength() {
        GeneratePasswordRequest request = new GeneratePasswordRequest();
        request.setLength(6);
        request.setUppercase(true);
        request.setCount(1);

        InvalidInputException exception = assertThrows(InvalidInputException.class, () -> service.generate(request));

        assertEquals("Password length must be between 8 and 64", exception.getMessage());
    }

    @Test
    void generateRejectsInvalidCount() {
        GeneratePasswordRequest request = new GeneratePasswordRequest();
        request.setLength(12);
        request.setUppercase(true);
        request.setCount(21);

        InvalidInputException exception = assertThrows(InvalidInputException.class, () -> service.generate(request));

        assertEquals("Count must be between 1 and 20", exception.getMessage());
    }

    @Test
    void generateWrapsUnexpectedGeneratorFailures() {
        PasswordUtil util = mock(PasswordUtil.class);
        PasswordGeneratorService failingService = new PasswordGeneratorService(util, new PasswordStrengthService());
        GeneratePasswordRequest request = new GeneratePasswordRequest();
        request.setLength(12);
        request.setUppercase(true);
        request.setLowercase(true);
        request.setNumbers(true);
        request.setCount(1);
        when(util.generate(12, true, true, true, false, false)).thenThrow(new RuntimeException("boom"));

        OperationFailedException exception = assertThrows(OperationFailedException.class,
                () -> failingService.generate(request));

        assertEquals("Password generation failed", exception.getMessage());
    }
}
