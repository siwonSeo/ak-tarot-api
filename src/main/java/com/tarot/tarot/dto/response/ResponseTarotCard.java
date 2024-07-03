package com.tarot.tarot.dto.response;

import java.util.List;

public record ResponseTarotCard(
          Integer cardId
        , Integer cardNumber
        , String cardNumberName
        , String cardType
        , String cardName
        , List<KeywordInfo> keywords) {
        public record KeywordInfo(Integer keywordId, boolean isReversed, String keyword){

        }

}
