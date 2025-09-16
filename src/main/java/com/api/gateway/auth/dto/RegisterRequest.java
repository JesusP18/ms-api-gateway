package com.api.gateway.auth.dto;

import javax.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {
    @NotEmpty(message = "no debe estar vacío")
    private String username;

    @NotEmpty(message = "no debe estar vacío")
    private String password;
}