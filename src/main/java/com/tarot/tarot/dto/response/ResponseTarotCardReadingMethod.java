package com.tarot.tarot.dto.response;

import java.util.List;

public record ResponseTarotCardReadingMethod(
          Integer cardCount
        , List<ReadingMethod> methods) {
        public record ReadingMethod(Integer methodId, String methodName, Integer methodOrder, String description){

        }

}
