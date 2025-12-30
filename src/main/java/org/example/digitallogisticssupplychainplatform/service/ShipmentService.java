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
public class ShipmentService {

    private final ShipmentRepository shipmentRepository;
    private final CarrierRepository carrierRepository;
    private final ShipmentMapper shipmentMapper;

    @Transactional(readOnly = true)
    public List<ShipmentDTO> findAll() {
        return shipmentRepository.findAll().stream()
                .map(shipmentMapper::toDTO)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public ShipmentDTO findById(Long id) {
        Shipment shipment = shipmentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Shipment not found with id: " + id));
        return shipmentMapper.toDTO(shipment);
    }

    @Transactional(readOnly = true)
    public List<ShipmentDTO> findByCarrierId(Long carrierId) {
        return shipmentRepository.findByCarrierId(carrierId).stream()
                .map(shipmentMapper::toDTO)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<ShipmentDTO> findByStatus(String status) {
        ShipmentStatus shipmentStatus = ShipmentStatus.valueOf(status);
        return shipmentRepository.findByStatus(shipmentStatus).stream()
                .map(shipmentMapper::toDTO)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public ShipmentDTO findByTrackingNumber(String trackingNumber) {
        Shipment shipment = shipmentRepository.findByTrackingNumber(trackingNumber)
                .orElseThrow(() -> new ResourceNotFoundException("Shipment not found with tracking: " + trackingNumber));
        return shipmentMapper.toDTO(shipment);
    }

    public ShipmentDTO create(ShipmentCreateDTO dto) {
        Carrier carrier = carrierRepository.findById(dto.getCarrierId())
                .orElseThrow(() -> new ResourceNotFoundException("Carrier not found with id: " + dto.getCarrierId()));

        if (shipmentRepository.existsByTrackingNumber(dto.getTrackingNumber())) {
            throw new DuplicateResourceException("Tracking number already exists: " + dto.getTrackingNumber());
        }

        Shipment shipment = shipmentMapper.toEntity(dto, carrier);
        Shipment saved = shipmentRepository.save(shipment);
        return shipmentMapper.toDTO(saved);
    }

    public ShipmentDTO update(Long id, ShipmentUpdateDTO dto) {
        Shipment shipment = shipmentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Shipment not found with id: " + id));

        Carrier carrier = null;
        if (dto.getCarrierId() != null) {
            carrier = carrierRepository.findById(dto.getCarrierId())
                    .orElseThrow(() -> new ResourceNotFoundException("Carrier not found with id: " + dto.getCarrierId()));
        }

        if (dto.getTrackingNumber() != null &&
                !dto.getTrackingNumber().equals(shipment.getTrackingNumber()) &&
                shipmentRepository.existsByTrackingNumber(dto.getTrackingNumber())) {
            throw new DuplicateResourceException("Tracking number already exists: " + dto.getTrackingNumber());
        }

        shipmentMapper.updateEntityFromDTO(dto, shipment, carrier);
        Shipment updated = shipmentRepository.save(shipment);
        return shipmentMapper.toDTO(updated);
    }

    public void delete(Long id) {
        if (!shipmentRepository.existsById(id)) {
            throw new ResourceNotFoundException("Shipment not found with id: " + id);
        }
        shipmentRepository.deleteById(id);
    }
}
