package com.api.gateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class JwtReactiveAuthenticationManager implements ReactiveAuthenticationManager {

    private final JwtUtil jwtUtil;

    public JwtReactiveAuthenticationManager(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        String token = (authentication == null || authentication.getCredentials() == null)
                ? null
                : authentication.getCredentials().toString();

        if (token == null || token.isBlank()) {
            return Mono.empty();
        }

        try {
            Jws<Claims> claims = jwtUtil.validateToken(token);
            Claims body = claims.getBody();
            String userId = body.getSubject();
            String roles = body.get("roles", String.class);

            List<SimpleGrantedAuthority> authorities = (roles == null || roles.isBlank())
                    ? List.of()
                    : Arrays.stream(roles.split(","))
                            .map(SimpleGrantedAuthority::new)
                            .collect(Collectors.toList());

            Authentication auth = new UsernamePasswordAuthenticationToken(userId, token, authorities);
            return Mono.just(auth);
        } catch (Exception e) {
            // token inválido / expirado -> no autenticado
            return Mono.empty();
        }
    }
}
