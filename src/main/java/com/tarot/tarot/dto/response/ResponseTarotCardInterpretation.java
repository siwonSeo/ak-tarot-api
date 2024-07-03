package com.tarot.tarot.dto.response;

import java.util.List;

public record ResponseTarotCardInterpretation(
          Integer cardId
        , Integer cardNumber
        , String cardNumberName
        , String cardType
        , String cardName
        , List<Category> categories) {
        public record Category(
                 char categoryCode
                ,String categoryName
                ,List<Interpretation> interpretations
        ){
                public record Interpretation(
                          boolean isReversed
                        , List<String> contents
                ){
                }
        }
}
