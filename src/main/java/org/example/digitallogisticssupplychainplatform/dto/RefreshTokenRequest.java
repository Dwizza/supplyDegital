package org.example.digitallogisticssupplychainplatform.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class RefreshTokenRequest {
    @NotBlank(message = "Le refresh token est obligatoire")
    private String refreshToken;
}