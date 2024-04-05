package com.example.jwtauth.controllers;

import com.example.jwtauth.dtos.LoginRequest;
import com.example.jwtauth.dtos.RegistrationRequest;
import com.example.jwtauth.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {


    private final UserService userService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest){
        return userService.createAuthToken(loginRequest);
    }

    @PostMapping("/registration")
    public ResponseEntity<?> registration(@RequestBody RegistrationRequest registrationRequest){
        return userService.saveUser(registrationRequest);
    }
}
