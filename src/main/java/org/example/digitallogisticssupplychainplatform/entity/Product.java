package org.example.digitallogisticssupplychainplatform.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "products")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Product {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String code;

    @Column(nullable = false)
    private String name;

    private String description;

    @Column(name = "main_style")
    private String mainStyle;

    @Column(name = "option_level")
    private Integer optionLevel;

    private String category;

    private String configuration;

    @Column(name = "base_type")
    private String base;

    @Column(name = "actual_email")
    private String actualEmail;

    @Builder.Default
    private Boolean active = true;

    @Builder.Default
    private Boolean index = false;

    @Column(name = "profile_type")
    private String profile;

    @Column(name = "created_date")
    @Builder.Default
    private LocalDateTime createdDate = LocalDateTime.now();

    @Column(name = "last_modified_date")
    @Builder.Default
    private LocalDateTime lastModifiedDate = LocalDateTime.now();

    @Enumerated(EnumType.STRING)
    @Builder.Default
    private ProductStatus status = ProductStatus.ACTIVE;

    public boolean isActive() {
        return active;
    }
}