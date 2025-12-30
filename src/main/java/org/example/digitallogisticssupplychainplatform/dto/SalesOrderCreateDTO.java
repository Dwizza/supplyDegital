package org.example.digitallogisticssupplychainplatform.dto;

import jakarta.validation.constraints.*;
import lombok.*;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SalesOrderCreateDTO {

    @NotNull(message = "Client ID is required")
    private Long clientId;

    @NotEmpty(message = "Order must contain at least one line")
    private List<SalesOrderLineCreateDTO> orderLines;
}
