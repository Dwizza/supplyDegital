package org.example.digitallogisticssupplychainplatform.service;
import org.example.digitallogisticssupplychainplatform.dto.*;
import org.example.digitallogisticssupplychainplatform.entity.*;
import org.example.digitallogisticssupplychainplatform.mapper.*;
import org.example.digitallogisticssupplychainplatform.repository.*;
import org.example.digitallogisticssupplychainplatform.exception.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;
import java.util.stream.Collectors;
@Service
@RequiredArgsConstructor
@Transactional
public class SalesOrderService {

    private final SalesOrderRepository salesOrderRepository;
    private final ProductRepository productRepository;
    private final SalesOrderMapper salesOrderMapper;
    private final UserRepository clientRepository;

    @Transactional(readOnly = true)
    public List<SalesOrderDTO> findAll() {
        return salesOrderRepository.findAll().stream()
                .map(salesOrderMapper::toDTO)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public SalesOrderDTO findById(Long id) {
        SalesOrder order = salesOrderRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Sales order not found with id: " + id));
        return salesOrderMapper.toDTO(order);
    }

    @Transactional(readOnly = true)
    public List<SalesOrderDTO> findByClientId(Long clientId) {
        return salesOrderRepository.findByClientId(clientId).stream()
                .map(salesOrderMapper::toDTO)
                .collect(Collectors.toList());
    }

    public SalesOrderDTO create(SalesOrderCreateDTO dto) {
        User client = clientRepository.findById(dto.getClientId())
                .orElseThrow(() -> new ResourceNotFoundException("Client not found with id: " + dto.getClientId()));

        for (var lineDTO : dto.getOrderLines()) {
            if (!productRepository.existsById(lineDTO.getProductId())) {
                throw new ResourceNotFoundException("Product not found with id: " + lineDTO.getProductId());
            }
        }

        SalesOrder order = salesOrderMapper.toEntity(dto, client);
        for (int i = 0; i < dto.getOrderLines().size(); i++) {
            Long productId = dto.getOrderLines().get(i).getProductId();
            Product product = productRepository.findById(productId).get();
            order.getOrderLines().get(i).setProduct(product);
        }

        SalesOrder saved = salesOrderRepository.save(order);
        return salesOrderMapper.toDTO(saved);
    }

    public SalesOrderDTO update(Long id, SalesOrderUpdateDTO dto) {
        SalesOrder order = salesOrderRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Sales order not found with id: " + id));

        salesOrderMapper.updateEntityFromDTO(dto, order);
        SalesOrder updated = salesOrderRepository.save(order);
        return salesOrderMapper.toDTO(updated);
    }

    public void delete(Long id) {
        if (!salesOrderRepository.existsById(id)) {
            throw new ResourceNotFoundException("Sales order not found with id: " + id);
        }
        salesOrderRepository.deleteById(id);
    }
}
