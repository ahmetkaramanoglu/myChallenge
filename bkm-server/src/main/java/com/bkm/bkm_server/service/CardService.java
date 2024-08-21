package com.bkm.bkm_server.service;

import com.bkm.bkm_server.dto.CardDto;
import com.bkm.bkm_server.dto.converter.CardDtoConverter;
import com.bkm.bkm_server.repository.CardRepository;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class CardService {
    private final CardRepository cardRepository;
    private final CardDtoConverter cardDtoConverter;
    public CardDto getAllCards() {
        return cardDtoConverter.convertCardToCardDto(cardRepository.findAll().get(0));
    }
}
