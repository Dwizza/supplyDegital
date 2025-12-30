package org.example.digitallogisticssupplychainplatform.service;

import lombok.Builder;
import lombok.RequiredArgsConstructor;
import org.example.digitallogisticssupplychainplatform.dto.CarrierDTO;
import org.example.digitallogisticssupplychainplatform.entity.Carrier;
import org.example.digitallogisticssupplychainplatform.entity.CarrierStatus;
import org.example.digitallogisticssupplychainplatform.mapper.CarrierMapper;
import org.example.digitallogisticssupplychainplatform.repository.CarrierRepository;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
@Builder
@RequiredArgsConstructor
public class CarrierService {
    private final CarrierRepository repo;
    private final CarrierMapper mapper;

    public CarrierDTO save(CarrierDTO carrierDTO){
        Carrier carrier=mapper.toEntity(carrierDTO);
        Carrier carrierSaved=repo.save(carrier);
        CarrierDTO result=mapper.toDto(carrierSaved);
        return result;
    }
    public List<CarrierDTO> findAll(){
        return repo.findAll().stream().map(mapper::toDto).toList();
    }

    public CarrierDTO findById(Long id){
        return repo.findById(id).map(mapper::toDto).orElseThrow(()->new RuntimeException("Carrier avec id specifie pas trouve"));
    }

    public CarrierDTO update(Long id, CarrierDTO carrierDTO) {
        Carrier existingCarrier = repo.findById(id)
                .orElseThrow(() -> new RuntimeException("Carrier non trouvé avec id: " + id));
        existingCarrier.setCode(carrierDTO.getCode());
        existingCarrier.setName(carrierDTO.getName());
        existingCarrier.setContactEmail(carrierDTO.getContactEmail());
        existingCarrier.setContactPhone(carrierDTO.getContactPhone());
        existingCarrier.setBaseShippingRate(carrierDTO.getBaseShippingRate());
        existingCarrier.setMaxDailyCapacity(carrierDTO.getMaxDailyCapacity());
        existingCarrier.setCurrentDailyShipments(carrierDTO.getCurrentDailyShipments());
        existingCarrier.setCutOffTime(carrierDTO.getCutOffTime());
        existingCarrier.setStatus(carrierDTO.getStatus());

        Carrier updatedCarrier = repo.save(existingCarrier);
        return mapper.toDto(updatedCarrier);
    }


    public void delete(Long id) {
        Carrier carrier = repo.findById(id)
                .orElseThrow(() -> new RuntimeException("Carrier non trouvé avec id: " + id));


        repo.delete(carrier);
    }

    public CarrierDTO updateStatus(Long id, String status) {
        Carrier carrier = repo.findById(id)
                .orElseThrow(() -> new RuntimeException("Carrier non trouvé avec id: " + id));

        carrier.setStatus(CarrierStatus.valueOf(status));
        Carrier updatedCarrier = repo.save(carrier);
        return mapper.toDto(updatedCarrier);
    }
}
