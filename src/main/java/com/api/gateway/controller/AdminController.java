package com.api.gateway.controller;

import com.api.gateway.entity.User;
import com.api.gateway.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final AuthService authService;

    public AdminController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * Endpoint para hacer admin a un usuario (solo para administradores)
     */
    @PatchMapping("/make-admin/{username}")
    public Mono<ResponseEntity<User>> makeAdmin(@PathVariable String username) {
        return authService.makeAdmin(username)
                .map(ResponseEntity::ok)
                .onErrorResume(e -> Mono.just(ResponseEntity.badRequest().build()));
    }
}