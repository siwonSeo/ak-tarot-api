package com.tarot.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tarot.tarot.dto.request.RequestTarotCard;
import com.tarot.tarot.service.TarotService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

@RequiredArgsConstructor
@Controller
public class TarotController {
    private final TarotService tarotService;

    @GetMapping("/")
    public String index(Model model) {
//        model.addAttribute("cards", tarotService.getTarotCards());
        model.addAttribute("categories", tarotService.getCardCategories());
        model.addAttribute("readingMethods", tarotService.getTaroCardReadingMethods());
        return "main";
    }

    @GetMapping("/card/select/auto/result")
    public String auto(Model model,
                       @RequestParam(name = "cardCount") int cardCount
            , @RequestParam(name = "isReverseOn") Boolean isReverseOn //역방향 활성화 여부
            , @RequestParam(name = "categoryCode") Character categoryCode
    ) {
        model.addAttribute("isReverseOn", isReverseOn);
        model.addAttribute("category", tarotService.getCardCategorie(categoryCode));
        model.addAttribute("reading", tarotService.getTaroCardReading(cardCount));
        model.addAttribute("cards", tarotService.getTaroCardConsultsByRandom(cardCount, isReverseOn, categoryCode));
        return "selected";
    }

    //수동선택
    @GetMapping("/card/select/self")
    public String select(Model model,
                         @RequestParam(name = "cardCount") int cardCount
            , @RequestParam(name = "isReverseOn") Boolean isReverseOn //역방향 활성화 여부
            , @RequestParam(name = "categoryCode") Character categoryCode
    ) {
        model.addAttribute("cardCount", cardCount);
        model.addAttribute("isReverseOn", isReverseOn);
        model.addAttribute("categoryCode", categoryCode);
        model.addAttribute("cards", tarotService.getTarotCardsRandom());
        return "select";
    }

    @PostMapping("/card/select/self/result")
    public String selfResult(Model model,
         @RequestParam("cardCount") int cardCount,
         @RequestParam("isReverseOn") Boolean isReverseOn,
         @RequestParam("categoryCode") Character categoryCode,
         @RequestParam("searchCards") String searchCards)
    {
        ObjectMapper mapper = new ObjectMapper();
        List<RequestTarotCard.TarotCardSearch> cards;
        try {
            cards = mapper.readValue(searchCards, new TypeReference<List<RequestTarotCard.TarotCardSearch>>() {});
        } catch (Exception e) {
            return "error.html";
        }

        model.addAttribute("isReverseOn", isReverseOn);
        model.addAttribute("category", tarotService.getCardCategorie(categoryCode));
        model.addAttribute("reading", tarotService.getTaroCardReading(cardCount));
        model.addAttribute("cards", tarotService.getTaroCardConsultsBySelf(cardCount,isReverseOn,categoryCode,cards));
        return "selected";
    }

    @GetMapping("/card/intro")
    public String intro(Model model) {
        model.addAttribute("cardGroups", tarotService.getTaroCardsIntro());
        return "intro";
    }

    @GetMapping("/card/reading")
    public String reading(Model model) {
        model.addAttribute("readings", tarotService.getTaroCardReadings());
        return "reading";
    }
}
