package org.example.digitallogisticssupplychainplatform.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name ="warehouses")
@Setter
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor

public class WareHouse {
@Id
@GeneratedValue(strategy =GenerationType.IDENTITY)
private Long id;
@Column(nullable = false)
private String name;
@Column(nullable = false)
private String code;
@Column(nullable = false)
@Builder.Default
private boolean active=true;
}
