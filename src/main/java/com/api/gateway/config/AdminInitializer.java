package com.api.gateway.config;

import com.api.gateway.entity.Role;
import com.api.gateway.entity.User;
import com.api.gateway.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
public class AdminInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AdminInitializer(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        // Verificar si ya existe un admin
        userRepository.findByUsername("admin")
                .switchIfEmpty(userRepository.save(
                        new User(null, "admin", passwordEncoder.encode("123456"),
                                Set.of(Role.USER, Role.ADMIN), null)
                ))
                .subscribe();
    }
}