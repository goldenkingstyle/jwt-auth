package com.example.jwtauth.entities;


import jakarta.persistence.*;
import lombok.Data;

import java.util.Collection;

@Entity
@Table(name = "users")
@Data
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;
    private String password;
    @ElementCollection
    private Collection<Role> roles;
}
