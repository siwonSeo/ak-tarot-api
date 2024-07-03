package com.tarot.tarot.repository;

import com.tarot.tarot.dto.request.RequestTarotCard;
import com.tarot.tarot.dto.response.*;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface TarotCardRepositoryCustom {
    ResponseTarotCardKeyword findTaroCardByCardId(int cardId);
    List<ResponseTarotCardRandom> findTaroCardRandom();

    ResponseTarotCardReading findTaroCardReading(int cardCount);
    List<ResponseTarotCardReading> findTaroCardReadings();
    ResponseTarotCardReadingMethod findTaroCardReadingMethod(int cardCount);
    List<ResponseTarotCardReadingMethod> findTaroCardReadingMethods();
    List<ResponseTarotCard> findTaroCardKewords(List<RequestTarotCard.TarotCardSearch> params);
    List<ResponseTarotCardInterpretation> findTaroCardInterpretations(List<RequestTarotCard.TarotCardSearch> params);
    List<ResponseTarotCardConsult> findTaroCardConsults(List<RequestTarotCard.TarotCardSearch> params);
    List<ResponseTarotCardIntro> findTaroCardsIntro();
}
