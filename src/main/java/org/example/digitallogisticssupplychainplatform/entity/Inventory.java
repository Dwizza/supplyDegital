package org.example.digitallogisticssupplychainplatform.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "inventories",
        uniqueConstraints = @UniqueConstraint(
                columnNames = {"product_id", "warehouse_id"}
        ))
@Setter
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Inventory {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "qty_on_hand")
    private Integer qtyOnHand = 0;

    @Column(name = "qty_reserved")
    private Integer qtyReserved = 0;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "warehouse_id", nullable = false)
    private WareHouse warehouse;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "product_id", nullable = false)
    private Product product;
}