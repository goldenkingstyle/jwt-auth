package com.example.jwtauth.dtos;

import lombok.Data;

@Data
public class RegistrationRequest {
    private String username;
    private String password;
}
