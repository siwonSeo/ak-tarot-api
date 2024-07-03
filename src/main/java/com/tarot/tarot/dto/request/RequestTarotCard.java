package com.tarot.tarot.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import org.springframework.lang.Nullable;

import java.util.List;

public record RequestTarotCard(
        List<TarotCardSearch> searchCards
          ) {
    public record TarotCardSearch(
                @Schema(description = "카드ID", example = "0")
                Integer cardId
            , @Schema(description = "역방향여부", example = "true")
                @Nullable Boolean isReversed
            , @Schema(description = "카테고리", example = "A")
              @Nullable Character categoryCode
    ){
    }
}
