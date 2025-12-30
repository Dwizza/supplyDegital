package org.example.digitallogisticssupplychainplatform.dto;

import lombok.*;

@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class SupplierDTO {

    private Long id;
    private String name;
    private String contactInfo;
}
