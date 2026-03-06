package com.passwordmanager.security.service;

import com.passwordmanager.security.dto.GeneratePasswordRequest;
import com.passwordmanager.security.dto.PasswordResponse;
import com.passwordmanager.security.exception.InvalidInputException;
import com.passwordmanager.security.exception.OperationFailedException;
import com.passwordmanager.security.util.PasswordUtil;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class PasswordGeneratorService {

    private final PasswordUtil util;
    private final PasswordStrengthService strengthService;

    public PasswordGeneratorService(PasswordUtil util, PasswordStrengthService strengthService) {
        this.util = util;
        this.strengthService = strengthService;
    }

    public List<PasswordResponse> generate(GeneratePasswordRequest req) {
        if (req.getLength() < 8 || req.getLength() > 64) {
            throw new InvalidInputException("Password length must be between 8 and 64");
        }

        if (!req.isUppercase() && !req.isLowercase() && !req.isNumbers() && !req.isSpecialChars()) {
            throw new InvalidInputException("Select at least one character type");
        }

        if (req.getCount() <= 0 || req.getCount() > 20) {
            throw new InvalidInputException("Count must be between 1 and 20");
        }

        List<PasswordResponse> list = new ArrayList<>();
        try {
            for (int i = 0; i < req.getCount(); i++) {
                String pass = util.generate(
                        req.getLength(),
                        req.isUppercase(),
                        req.isLowercase(),
                        req.isNumbers(),
                        req.isSpecialChars(),
                        req.isExcludeSimilar()
                );

                list.add(new PasswordResponse(pass, strengthService.checkStrength(pass)));
            }
        } catch (Exception e) {
            throw new OperationFailedException("Password generation failed");
        }

        return list;
    }
}
