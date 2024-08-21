package com.bkm.bkm_server.dto.converter;

import com.bkm.bkm_server.dto.CardDto;
import com.bkm.bkm_server.model.Card;
import org.springframework.stereotype.Component;

@Component
public class CardDtoConverter {
    public CardDto convertCardToCardDto(Card card) {
        return new CardDto(card.getCardHolder());
    }
}
