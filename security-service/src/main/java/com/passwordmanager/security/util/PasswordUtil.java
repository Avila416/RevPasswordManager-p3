package com.passwordmanager.security.util;

import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Component
public class PasswordUtil {

    private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String NUM = "0123456789";
    private static final String SPECIAL = "@#$%&*!?";
    private static final String SIMILAR = "0O1lI";

    private final SecureRandom random = new SecureRandom();

    public String generate(int length,
                           boolean upper,
                           boolean lower,
                           boolean num,
                           boolean special,
                           boolean excludeSimilar) {
        String upperSet = excludeSimilar ? removeSimilar(UPPER) : UPPER;
        String lowerSet = excludeSimilar ? removeSimilar(LOWER) : LOWER;
        String numSet = excludeSimilar ? removeSimilar(NUM) : NUM;
        String specialSet = SPECIAL;

        StringBuilder pool = new StringBuilder();
        List<Character> mandatory = new ArrayList<>();

        if (upper) {
            pool.append(upperSet);
            mandatory.add(randomChar(upperSet));
        }
        if (lower) {
            pool.append(lowerSet);
            mandatory.add(randomChar(lowerSet));
        }
        if (num) {
            pool.append(numSet);
            mandatory.add(randomChar(numSet));
        }
        if (special) {
            pool.append(specialSet);
            mandatory.add(randomChar(specialSet));
        }

        if (pool.isEmpty()) {
            throw new IllegalArgumentException("No character set selected");
        }
        if (length < mandatory.size()) {
            throw new IllegalArgumentException("Length is too short for selected character types");
        }

        List<Character> passwordChars = new ArrayList<>(mandatory);
        while (passwordChars.size() < length) {
            passwordChars.add(randomChar(pool.toString()));
        }

        Collections.shuffle(passwordChars, random);
        StringBuilder out = new StringBuilder();
        for (Character c : passwordChars) {
            out.append(c);
        }
        return out.toString();
    }

    private String removeSimilar(String source) {
        String result = source;
        for (char c : SIMILAR.toCharArray()) {
            result = result.replace(String.valueOf(c), "");
        }
        return result;
    }

    private char randomChar(String source) {
        if (source == null || source.isEmpty()) {
            throw new IllegalArgumentException("Character source is empty");
        }
        return source.charAt(random.nextInt(source.length()));
    }
}
