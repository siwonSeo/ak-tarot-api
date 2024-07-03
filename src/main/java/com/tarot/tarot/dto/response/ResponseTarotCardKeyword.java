package com.tarot.tarot.dto.response;

import java.util.List;

public record ResponseTarotCardKeyword(
          Integer cardId
        , Integer cardNumber
        , String cardNumberName
        , String cardType
        , String cardName
        , List<KeywordInfo> forwardKeywords
        , List<KeywordInfo> reverseKeywords) {
        public record KeywordInfo(Integer keywordId, String keyword){

        }

}
