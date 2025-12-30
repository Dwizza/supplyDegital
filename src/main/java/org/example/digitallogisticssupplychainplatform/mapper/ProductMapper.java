package org.example.digitallogisticssupplychainplatform.mapper;

import org.example.digitallogisticssupplychainplatform.dto.ProductDTO;
import org.example.digitallogisticssupplychainplatform.entity.Product;
import org.springframework.stereotype.Component;

@Component
public class ProductMapper {

    public ProductDTO toDto(Product product) {
        if (product == null) {
            return null;
        }

        return ProductDTO.builder()
                .id(product.getId())
                .code(product.getCode())
                .name(product.getName())
                .description(product.getDescription())
                .mainStyle(product.getMainStyle())
                .optionLevel(product.getOptionLevel())
                .category(product.getCategory())
                .configuration(product.getConfiguration())
                .base(product.getBase())
                .actualEmail(product.getActualEmail())
                .active(product.getActive())
                .index(product.getIndex())
                .profile(product.getProfile())
                .status(product.getStatus() != null ? product.getStatus().name() : null)
                .build();
    }

    public Product toEntity(ProductDTO productDTO) {
        if (productDTO == null) {
            return null;
        }

        return Product.builder()
                .id(productDTO.getId())
                .code(productDTO.getCode())
                .name(productDTO.getName())
                .description(productDTO.getDescription())
                .mainStyle(productDTO.getMainStyle())
                .optionLevel(productDTO.getOptionLevel())
                .category(productDTO.getCategory())
                .configuration(productDTO.getConfiguration())
                .base(productDTO.getBase())
                .actualEmail(productDTO.getActualEmail())
                .active(productDTO.getActive())
                .index(productDTO.getIndex())
                .profile(productDTO.getProfile())
                .build();
    }
}