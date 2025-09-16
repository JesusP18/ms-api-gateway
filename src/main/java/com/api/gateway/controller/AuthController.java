package com.api.gateway.controller;

import com.api.gateway.auth.dto.LoginRequest;
import com.api.gateway.auth.dto.RegisterRequest;
import com.api.gateway.entity.User;
import com.api.gateway.service.AuthService;
import com.api.gateway.auth.dto.AuthResponse;
import javax.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * Endpoint para iniciar sesión
     */
    @PostMapping("/login")
    public Mono<ResponseEntity<AuthResponse>> login(@Valid @RequestBody LoginRequest request) {
        return authService.login(request)
                .map(ResponseEntity::ok)
                .onErrorResume(e -> Mono.error(new RuntimeException(e.getMessage())));
    }

    /**
     * Endpoint para registrar un nuevo usuario
     */
    @PostMapping("/register")
    public Mono<ResponseEntity<AuthResponse>> register(@Valid @RequestBody RegisterRequest request) {
        return authService.register(request)
                .map(ResponseEntity::ok)
                .onErrorResume(e -> Mono.error(new RuntimeException(e.getMessage())));
    }

    /**
     * Endpoint para validar un token JWT
     */
    @GetMapping("/validate-token")
    public Mono<ResponseEntity<Boolean>> validate(@RequestParam String token) {
        return authService.validateToken(token)
                .map(ResponseEntity::ok);
    }
}
