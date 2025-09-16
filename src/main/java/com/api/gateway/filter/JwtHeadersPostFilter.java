package com.api.gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import java.util.stream.Collectors;

@Component
public class JwtHeadersPostFilter implements GlobalFilter, Ordered {
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication())
                .filter(auth -> auth != null && auth.isAuthenticated()) // Filtra autenticaciones válidas
                .flatMap(auth -> {
                    String userId = auth.getPrincipal() == null ? "" : auth.getPrincipal().toString();
                    String roles = auth.getAuthorities() == null ? "" :
                            auth.getAuthorities().stream().map(Object::toString).collect(Collectors.joining(","));

                    ServerHttpRequest.Builder reqBuilder = exchange.getRequest().mutate();
                    reqBuilder.headers(h -> {
                        h.remove("X-User-Id");
                        h.remove("X-Customer-Id");
                        h.remove("X-Roles");
                        if (!userId.isBlank()) h.add("X-User-Id", userId);
                        if (!roles.isBlank()) h.add("X-Roles", roles);
                    });

                    ServerHttpRequest mutated = reqBuilder.build();
                    return chain.filter(exchange.mutate().request(mutated).build());
                })
                .switchIfEmpty(chain.filter(exchange)); // Si no hay autenticación, continúa sin modificar
    }

    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }
}
