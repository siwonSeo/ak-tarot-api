package com.tarot.tarot.controller;

import com.tarot.tarot.dto.request.RequestTarotCard;
import com.tarot.tarot.dto.response.*;
import com.tarot.tarot.service.TarotService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RequiredArgsConstructor
@RequestMapping("/api")
@RestController
public class TarotApiController {
    private final TarotService tarotService;


    @Tag(name="타로 인트로")
    @Operation(summary = "카드 인트로", description = "카드 인트로")
    @GetMapping("/card/intro")
    public ResponseEntity<List<ResponseTarotCardIntro>> intro() {
        return new ResponseEntity<>(tarotService.getTaroCardsIntro(), HttpStatus.OK);
    }

    @Tag(name="타로 인트로")
    @Operation(summary = "리딩 방법", description = "리딩 방법")
    @GetMapping("/card/reading-methods")
    public ResponseEntity<List<ResponseTarotCardReadingMethod>> readingMethods() {
        return new ResponseEntity<>(tarotService.getTaroCardReadingMethods(), HttpStatus.OK);
    }

    @Tag(name="카드")
    @Operation(summary = "카드 기본정보", description = "키워드")
    @GetMapping("/card/{cardId}")
    public ResponseEntity<ResponseTarotCardKeyword> getTaroCard(@PathVariable("cardId") int cardId) {
        return new ResponseEntity<>(tarotService.getTaroCard(cardId), HttpStatus.OK);
    }

    @Tag(name="카드")
    @Operation(summary = "카드 상담(수동)", description = "카드 해석(수동)")
    @PostMapping("/card/consult/self")
    public ResponseEntity<List<ResponseTarotCardConsult>> getTaroCardConsultSelf(
              @RequestParam(name = "cardCount") int cardCount
            , @RequestParam(name = "isReverseOn") Boolean isReverseOn //역방향 활성화 여부
            , @RequestParam(name = "categoryCode") Character categoryCode
            , @RequestBody List<RequestTarotCard.TarotCardSearch> cards) {
        return new ResponseEntity<>(tarotService.getTaroCardConsultsBySelf(cardCount, isReverseOn, categoryCode, cards), HttpStatus.OK);
    }

    @Tag(name="카드")
    @Operation(summary = "카드 상담(랜덤)", description = "카드 상담(랜덤)")
    @GetMapping("/card/consult/random")
    public ResponseEntity<List<ResponseTarotCardConsult>> getTaroCardConsultAuto(
              @RequestParam(name = "cardCount") int cardCount
            , @RequestParam(name = "isReverseOn") Boolean isReverseOn //역방향 활성화 여부
            , @RequestParam(name = "categoryCode") Character categoryCode) {
        return new ResponseEntity<>(tarotService.getTaroCardConsultsByRandom(cardCount, isReverseOn, categoryCode), HttpStatus.OK);
    }

    @Tag(name="카드")
    @Operation(summary = "카드 해석정보 검색(수동)", description = "카드 해석정보")
    @PostMapping("/card/interpretation/search")
    public ResponseEntity<List<ResponseTarotCardInterpretation>> getTaroCardInterpretations(@RequestBody RequestTarotCard param) {
        return new ResponseEntity<>(tarotService.getTaroCardInterpretations(param.searchCards()), HttpStatus.OK);
    }

    @Tag(name="카드")
    @Operation(summary = "카드 해석정보 검색(랜덤)", description = "카드 해석정보")
    @GetMapping("/card/interpretation/{cardCount}")
    public ResponseEntity<List<ResponseTarotCardInterpretation>> getTaroCardInterpretations(
            @PathVariable("cardCount") int cardCount
            , @RequestParam(name = "isReverseOn", required = false) Boolean isReverseOn //역방향 활성화 여부
            , @RequestParam(name = "categoryCode", required = false) Character categoryCode

    ) {
        return new ResponseEntity<>(tarotService.getTaroCardInterpretationsByRandom(cardCount, isReverseOn, categoryCode), HttpStatus.OK);
    }

    @Tag(name="카드")
    @Operation(summary = "카드 키워드 검색", description = "카드 키워드 검색")
    @PostMapping("/card/keyword/search")
    public ResponseEntity<List<ResponseTarotCard>> getTaroCardKeyWords(@RequestBody RequestTarotCard param) {
        return new ResponseEntity<>(tarotService.getTaroCardKeyWords(param.searchCards()), HttpStatus.OK);
    }
}
