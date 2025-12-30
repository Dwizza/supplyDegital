package org.example.digitallogisticssupplychainplatform.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Builder
@Table(name="suppliers")
@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class Supplier {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)

    private Long id;
   @Column(nullable = false)
    private String name;
    @Column(nullable = false)
    private String contactInfo;

}
