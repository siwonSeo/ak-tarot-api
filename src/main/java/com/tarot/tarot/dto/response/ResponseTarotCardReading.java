package com.tarot.tarot.dto.response;

import java.util.List;

public record ResponseTarotCardReading(
          Integer cardCount
        , List<ReadingMethod> methods) {
        public record ReadingMethod(Integer methodId, String methodName, Integer methodOrder, String description, String positionsName){

        }

}
