package com.bkm.bkm_server.controller;


import com.bkm.bkm_server.annotation.decryption.Decrypted;
import com.bkm.bkm_server.dto.CardDto;
import com.bkm.bkm_server.response.BaseResponse;
import com.bkm.bkm_server.service.CardService;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/bkm/card")
@AllArgsConstructor
public class CardController {
    private final CardService cardService;
    @GetMapping("/cards")
    public BaseResponse<CardDto> getCard() {
        return new BaseResponse<>(cardService.getAllCards());
    }

    @PostMapping("/selamiAl")
    public String selamiAl(@Decrypted String selam) {
        System.out.println("selam duzgun calisiyor " + selam);
        return "Selam Kafatech!";
    }
}
