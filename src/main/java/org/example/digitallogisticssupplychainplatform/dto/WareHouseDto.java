package org.example.digitallogisticssupplychainplatform.dto;

import lombok.*;

@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class WareHouseDto {
    private Long id;
    private String name;
    private String code;
    private Boolean active;
}
