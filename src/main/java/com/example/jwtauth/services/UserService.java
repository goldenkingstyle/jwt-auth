package com.example.jwtauth.services;

import com.example.jwtauth.dtos.LoginRequest;
import com.example.jwtauth.dtos.RegistrationRequest;
import com.example.jwtauth.entities.Role;
import com.example.jwtauth.entities.User;
import com.example.jwtauth.repositories.UserRepository;
import com.example.jwtauth.utils.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.List;

@Service
@RequiredArgsConstructor
@Lazy
public class UserService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtUtils jwtUtils;
    private final PasswordEncoder passwordEncoder;
    private final UserDetailsService userDetailsService;

    public ResponseEntity<?> createAuthToken(@RequestBody LoginRequest jwtRequest){
        try{
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(jwtRequest.getUsername(), jwtRequest.getPassword()));
        } catch (BadCredentialsException e){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Bad credentials");
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(jwtRequest.getUsername());
        return ResponseEntity.ok(jwtUtils.generateToken(userDetails));
    }




    public ResponseEntity<?> saveUser(RegistrationRequest registrationRequest){
        User user = new User();
        user.setUsername(registrationRequest.getUsername());


        if(userRepository.findByUsername(user.getUsername()).isPresent()){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("User already exists");
        }

        user.setPassword(passwordEncoder.encode(registrationRequest.getPassword()));
        user.setRoles(List.of(Role.USER));

        userRepository.save(user);
        return ResponseEntity.ok().build();
    }
}
