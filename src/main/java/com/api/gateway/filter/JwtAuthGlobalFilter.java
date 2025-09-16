package com.api.gateway.filter;

import com.api.gateway.util.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;

import java.util.List;
import java.util.stream.Collectors;
import java.util.Arrays;

@Component
public class JwtAuthGlobalFilter implements GlobalFilter, Ordered {

    private final JwtUtil jwtUtil;

    public JwtAuthGlobalFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        System.out.println("[JwtAuthGlobalFilter] Request path: " + path);

        if (path.startsWith("/api/auth")) {
            System.out.println("[JwtAuthGlobalFilter] Endpoint público, se deja pasar sin validar token.");
            return chain.filter(exchange);
        }

        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        System.out.println("[JwtAuthGlobalFilter] Authorization header recibido: " + authHeader);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            System.err.println("[JwtAuthGlobalFilter] Token no encontrado o mal formado.");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7);
        try {
            System.out.println("[JwtAuthGlobalFilter] Validando token...");
            Jws<Claims> claims = jwtUtil.validateToken(token);
            Claims body = claims.getBody();

            String userId = body.getSubject();
            String customerId = body.get("customerId", String.class);
            String roles = body.get("roles", String.class);

            System.out.println("[JwtAuthGlobalFilter] Token válido. Usuario: " + userId +
                    ", Roles: " + roles + ", CustomerId: " + customerId);

            // Crear Authentication
            List<SimpleGrantedAuthority> authorities = Arrays.stream(roles.split(","))
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());

            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(userId, null, authorities);

            // Agregar headers
            ServerHttpRequest mutated = exchange.getRequest().mutate()
                    .header("X-User-Id", userId)
                    .header("X-Customer-Id", customerId == null ? "" : customerId)
                    .header("X-Roles", roles == null ? "" : roles)
                    .build();

            ServerWebExchange mutatedExchange = exchange.mutate().request(mutated).build();

            System.out.println("[JwtAuthGlobalFilter] Autenticación inyectada en el contexto.");

            // Establecer autenticación en el contexto de seguridad
            return chain.filter(mutatedExchange)
                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
        } catch (Exception ex) {
            System.err.println("[JwtAuthGlobalFilter] Error validando token: " + ex.getMessage());
            ex.printStackTrace();
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }


    @Override
    public int getOrder() {
        return -100;
    }
}