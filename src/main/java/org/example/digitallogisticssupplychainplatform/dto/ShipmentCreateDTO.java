package org.example.digitallogisticssupplychainplatform.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.validation.constraints.*;
import lombok.*;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ShipmentCreateDTO {

    @NotBlank(message = "Tracking number is required")
    private String trackingNumber;


    @NotNull(message = "Carrier ID is required")
    private Long carrierId;

    @NotNull(message = "Planned date is required")
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime plannedDate;

    @NotNull(message = "Status is required")
    private String status;

    @Size(max = 500, message = "Description cannot exceed 500 characters")
    private String description;
}
