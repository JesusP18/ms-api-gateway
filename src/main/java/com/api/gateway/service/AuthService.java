package com.api.gateway.service;

import com.api.gateway.auth.dto.AuthResponse;
import com.api.gateway.auth.dto.LoginRequest;
import com.api.gateway.auth.dto.RegisterRequest;
import com.api.gateway.entity.Role;
import com.api.gateway.entity.User;
import com.api.gateway.repository.UserRepository;
import com.api.gateway.util.JwtUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Set;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    /**
     * Autentica a un usuario y genera un token JWT
     */
    public Mono<AuthResponse> login(LoginRequest request) {
        return userRepository.findByUsername(request.getUsername())
                .filter(user -> passwordEncoder.matches(request.getPassword(), user.getPassword()))
                .flatMap(user -> {
                    String token = jwtUtil.generateToken(
                            user.getId(),
                            user.getUsername(),
                            user.getCustomerId(),
                            rolesToString(user.getRoles())
                    );
                    long expiresIn = jwtUtil.getExpirationFromToken(token);
                    return Mono.just(new AuthResponse(token, expiresIn));
                })
                .switchIfEmpty(Mono.error(new RuntimeException("Credenciales inválidas")));
    }

    /**
     * Registra un nuevo usuario en el sistema
     */
    public Mono<AuthResponse> register(RegisterRequest request) {
        return userRepository.existsByUsername(request.getUsername())
                .flatMap(exists -> {
                    if (exists) {
                        return Mono.error(new RuntimeException("El nombre de usuario ya existe"));
                    }
                    User user = new User();
                    user.setUsername(request.getUsername());
                    user.setPassword(passwordEncoder.encode(request.getPassword()));
                    user.setRoles(Set.of(Role.USER));

                    return userRepository.save(user);
                })
                .flatMap(user -> {
                    String token = jwtUtil.generateToken(
                            user.getId(),
                            user.getUsername(),
                            user.getCustomerId(),
                            rolesToString(user.getRoles())
                    );
                    long expiresIn = jwtUtil.getExpirationFromToken(token);
                    return Mono.just(new AuthResponse(token, expiresIn));
                });
    }

    /**
     * Valida si un token JWT es válido
     */
    public Mono<Boolean> validateToken(String token) {
        try {
            jwtUtil.validateToken(token);
            return Mono.just(true);
        } catch (Exception e) {
            return Mono.just(false);
        }
    }

    /**
     * Convierte un conjunto de roles a una cadena CSV
     */
    private String rolesToString(Set<Role> roles) {
        return String.join(",", roles.stream().map(Enum::name).toArray(String[]::new));
    }
}