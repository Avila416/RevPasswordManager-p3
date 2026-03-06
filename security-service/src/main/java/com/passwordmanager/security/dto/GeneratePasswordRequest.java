package com.passwordmanager.security.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;

public class GeneratePasswordRequest {

    @Min(value = 8, message = "Length must be at least 8")
    @Max(value = 64, message = "Length must be at most 64")
    private int length;

    private boolean uppercase;
    private boolean lowercase;
    private boolean numbers;
    private boolean specialChars;
    private boolean excludeSimilar;

    @Min(value = 1, message = "Count must be at least 1")
    @Max(value = 20, message = "Count must be at most 20")
    private int count;

    public GeneratePasswordRequest() {
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }

    public boolean isUppercase() {
        return uppercase;
    }

    public void setUppercase(boolean uppercase) {
        this.uppercase = uppercase;
    }

    public boolean isLowercase() {
        return lowercase;
    }

    public void setLowercase(boolean lowercase) {
        this.lowercase = lowercase;
    }

    public boolean isNumbers() {
        return numbers;
    }

    public void setNumbers(boolean numbers) {
        this.numbers = numbers;
    }

    public boolean isSpecialChars() {
        return specialChars;
    }

    public void setSpecialChars(boolean specialChars) {
        this.specialChars = specialChars;
    }

    public boolean isExcludeSimilar() {
        return excludeSimilar;
    }

    public void setExcludeSimilar(boolean excludeSimilar) {
        this.excludeSimilar = excludeSimilar;
    }

    public int getCount() {
        return count;
    }

    public void setCount(int count) {
        this.count = count;
    }
}
