package com.api.gateway.config;

import com.api.gateway.util.JwtReactiveAuthenticationManager;
import com.api.gateway.util.JwtUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private final JwtUtil jwtUtil;

    public SecurityConfig(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Convierte la petición a un Authentication que contiene el token como credentials
    private ServerAuthenticationConverter bearerTokenConverter() {
        return exchange -> {
            String header = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (header == null || !header.startsWith("Bearer ")) {
                return Mono.empty();
            }
            String token = header.substring(7);
            // UsernamePasswordAuthenticationToken(principal, credentials)
            return Mono.just(new UsernamePasswordAuthenticationToken(null, token));
        };
    }

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {

        // AuthenticationWebFilter usando tu ReactiveAuthenticationManager
        JwtReactiveAuthenticationManager authManager = new JwtReactiveAuthenticationManager(jwtUtil);
        AuthenticationWebFilter authenticationWebFilter = new AuthenticationWebFilter(authManager);
        authenticationWebFilter.setServerAuthenticationConverter(bearerTokenConverter());
        // evitar que el filtro intente almacenar el contexto en un repo distinto (usaremos NoOp si quieres)
        authenticationWebFilter.setSecurityContextRepository(NoOpServerSecurityContextRepository.getInstance());

        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .addFilterBefore(authenticationWebFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/api/auth/**").permitAll()
                        .anyExchange().authenticated()
                )
                .build();
    }
}
