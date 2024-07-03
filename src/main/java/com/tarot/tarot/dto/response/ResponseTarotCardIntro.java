package com.tarot.tarot.dto.response;

import java.util.List;

public record ResponseTarotCardIntro(
          String cardType
        , List<CardInfo> keywords) {
        public record CardInfo(
                  Integer cardId
                , Integer cardNumber
                , String cardNumberName
                , String cardName
        ){

        }

}
