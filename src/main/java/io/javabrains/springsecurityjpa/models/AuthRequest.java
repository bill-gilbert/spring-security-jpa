package io.javabrains.springsecurityjpa.models;

import lombok.Data;

@Data
public class AuthRequest {
    private String name;
    private String password;
}
