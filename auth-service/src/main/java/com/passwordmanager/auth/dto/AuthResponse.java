package com.passwordmanager.auth.dto;

public class AuthResponse {

    private String token;
    private String tokenType;
    private UserDto user;
    private boolean requiresTwoFactor;

    public AuthResponse() {
    }

    public AuthResponse(String token, String tokenType, UserDto user, boolean requiresTwoFactor) {
        this.token = token;
        this.tokenType = tokenType;
        this.user = user;
        this.requiresTwoFactor = requiresTwoFactor;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public UserDto getUser() {
        return user;
    }

    public void setUser(UserDto user) {
        this.user = user;
    }

    public boolean isRequiresTwoFactor() {
        return requiresTwoFactor;
    }

    public void setRequiresTwoFactor(boolean requiresTwoFactor) {
        this.requiresTwoFactor = requiresTwoFactor;
    }

    public static AuthResponseBuilder builder() {
        return new AuthResponseBuilder();
    }

    public static class AuthResponseBuilder {
        private String token;
        private String tokenType;
        private UserDto user;
        private boolean requiresTwoFactor;

        public AuthResponseBuilder token(String token) {
            this.token = token;
            return this;
        }

        public AuthResponseBuilder tokenType(String tokenType) {
            this.tokenType = tokenType;
            return this;
        }

        public AuthResponseBuilder user(UserDto user) {
            this.user = user;
            return this;
        }

        public AuthResponseBuilder requiresTwoFactor(boolean requiresTwoFactor) {
            this.requiresTwoFactor = requiresTwoFactor;
            return this;
        }

        public AuthResponse build() {
            return new AuthResponse(token, tokenType, user, requiresTwoFactor);
        }
    }

    public static class UserDto {
        private Long id;
        private String username;
        private String email;
        private String firstName;
        private String lastName;
        private String role;
        private boolean hasMasterPassword;
        private boolean twoFactorEnabled;

        public UserDto() {
        }

        public UserDto(Long id, String username, String email, String firstName, String lastName,
                       String role, boolean hasMasterPassword, boolean twoFactorEnabled) {
            this.id = id;
            this.username = username;
            this.email = email;
            this.firstName = firstName;
            this.lastName = lastName;
            this.role = role;
            this.hasMasterPassword = hasMasterPassword;
            this.twoFactorEnabled = twoFactorEnabled;
        }

        public Long getId() {
            return id;
        }

        public void setId(Long id) {
            this.id = id;
        }

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getFirstName() {
            return firstName;
        }

        public void setFirstName(String firstName) {
            this.firstName = firstName;
        }

        public String getLastName() {
            return lastName;
        }

        public void setLastName(String lastName) {
            this.lastName = lastName;
        }

        public String getRole() {
            return role;
        }

        public void setRole(String role) {
            this.role = role;
        }

        public boolean isHasMasterPassword() {
            return hasMasterPassword;
        }

        public void setHasMasterPassword(boolean hasMasterPassword) {
            this.hasMasterPassword = hasMasterPassword;
        }

        public boolean isTwoFactorEnabled() {
            return twoFactorEnabled;
        }

        public void setTwoFactorEnabled(boolean twoFactorEnabled) {
            this.twoFactorEnabled = twoFactorEnabled;
        }

        public static UserDtoBuilder builder() {
            return new UserDtoBuilder();
        }

        public static class UserDtoBuilder {
            private Long id;
            private String username;
            private String email;
            private String firstName;
            private String lastName;
            private String role;
            private boolean hasMasterPassword;
            private boolean twoFactorEnabled;

            public UserDtoBuilder id(Long id) {
                this.id = id;
                return this;
            }

            public UserDtoBuilder username(String username) {
                this.username = username;
                return this;
            }

            public UserDtoBuilder email(String email) {
                this.email = email;
                return this;
            }

            public UserDtoBuilder firstName(String firstName) {
                this.firstName = firstName;
                return this;
            }

            public UserDtoBuilder lastName(String lastName) {
                this.lastName = lastName;
                return this;
            }

            public UserDtoBuilder role(String role) {
                this.role = role;
                return this;
            }

            public UserDtoBuilder hasMasterPassword(boolean hasMasterPassword) {
                this.hasMasterPassword = hasMasterPassword;
                return this;
            }

            public UserDtoBuilder twoFactorEnabled(boolean twoFactorEnabled) {
                this.twoFactorEnabled = twoFactorEnabled;
                return this;
            }

            public UserDto build() {
                return new UserDto(id, username, email, firstName, lastName, role, hasMasterPassword, twoFactorEnabled);
            }
        }
    }
}
