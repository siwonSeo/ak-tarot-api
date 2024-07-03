package com.tarot.tarot.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;

public record RequestTarotCardSelect(
        int cardCount,
        @Schema(description = "역방향포함 활성화", example = "true") Boolean isReverseOn,
        @Schema(description = "카테고리", example = "A") Character categoryCode,
        List<RequestTarotCard.TarotCardSearch> searchCards
          ) {

}
