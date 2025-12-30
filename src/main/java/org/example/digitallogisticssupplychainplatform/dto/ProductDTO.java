package org.example.digitallogisticssupplychainplatform.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProductDTO {
    private Long id;
    private String code;
    private String name;
    private String description;
    private String mainStyle;
    private Integer optionLevel;
    private String category;
    private String configuration;
    private String base;
    private String actualEmail;

    @Builder.Default
    private Boolean active = true;

    @Builder.Default
    private Boolean index = false;
    private String profile;
    private String status;
}