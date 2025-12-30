package org.example.digitallogisticssupplychainplatform.mapper;

import org.example.digitallogisticssupplychainplatform.dto.CarrierDTO;
import org.example.digitallogisticssupplychainplatform.entity.Carrier;
import org.springframework.stereotype.Component;

@Component
public class CarrierMapper {

    public Carrier toEntity(CarrierDTO carrierDTO){
        if(carrierDTO==null){
            return null;
        }

        return Carrier.builder().code(carrierDTO.getCode()).
                name(carrierDTO.getName()).
                contactEmail(carrierDTO.getContactEmail()).
                contactPhone(carrierDTO.getContactPhone()).
                baseShippingRate(carrierDTO.getBaseShippingRate()).
                maxDailyCapacity(carrierDTO.getMaxDailyCapacity()).
                currentDailyShipments(carrierDTO.getCurrentDailyShipments()).
                cutOffTime(carrierDTO.getCutOffTime()).
                status(carrierDTO.getStatus()).
                build();

    }

    public CarrierDTO toDto(Carrier carrier){
        if(carrier==null){
            return null;
        }

        return CarrierDTO.builder().code(carrier.getCode()).
                name(carrier.getName()).
                contactEmail(carrier.getContactEmail()).
                contactPhone(carrier.getContactPhone()).
                baseShippingRate(carrier.getBaseShippingRate()).
                maxDailyCapacity(carrier.getMaxDailyCapacity()).
                currentDailyShipments(carrier.getCurrentDailyShipments()).
                cutOffTime(carrier.getCutOffTime()).
                status(carrier.getStatus()).
                build();

    }

}
