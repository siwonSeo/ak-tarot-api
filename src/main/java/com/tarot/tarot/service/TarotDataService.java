package com.tarot.tarot.service;

import com.tarot.tarot.entity.*;
import com.tarot.tarot.repository.*;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
@Service
public class TarotDataService {
    private final TarotCardRepository tarotCardRepository;
    private final TarotCardKeyWordRepository tarotCardKeyWordRepository;
    private final TarotCardCategoryRepository tarotCardCategoryRepository;
    private final TarotCardInterpretationRepository tarotCardInterpretationRepository;
    private final TarotCardReadingMethodRepository tarotCardReadingMethodRepository;
    private final TarotCardReadingMethodPositionRepository tarotCardReadingMethodPositionRepository;

    @Transactional
    public void setDefaultData() throws IOException, ParseException {
        saveTarotCard();
        List<TarotCard> tarotCards = this.getTarotCards();

        //카테고리 저장
        try{
            this.saveCategory();
        }catch (Exception e){
            log.info("카테고리 exception:{}",e.getMessage());
        }

        for (TarotCard tarotCard : tarotCards) {
            try{
                this.saveInterpretation(tarotCard);
//                tarotCardInterpretationRepository.saveAll()
            }catch (Exception e){
                log.info("saveInterpretation exception:{}",e.getMessage());
            }
        }
        //리딩방법 저장
        try{
            this.saveReading();
        }catch (Exception e){
            log.info("리딩방법 exception:{}",e.getMessage());
        }
    }


    public List<TarotCard> getTarotCards(){
        return tarotCardRepository.findAll();
    }

    private void saveTarotCard() throws IOException, ParseException {
        JSONParser parser = new JSONParser();
        ClassPathResource resource = new ClassPathResource("data/기초데이터.json");
        Reader reader = new FileReader(resource.getFile(), StandardCharsets.UTF_8);
        JSONArray dataArray = (JSONArray) parser.parse(reader);
        log.info("dataArray:{}",dataArray);
        for(Object obj : dataArray){
            JSONObject jo = (JSONObject)obj;
            log.info("jo:{}",jo);
            TarotCard tarotCard = tarotCardRepository.save(new TarotCard(
                            Integer.parseInt(jo.get("cardId").toString())
                            ,Integer.parseInt(jo.get("cardNumber").toString())
                            ,jo.get("cardNumberName").toString()
                            ,jo.get("cardName").toString()
                            ,jo.get("cardType").toString()
                    )
            );

            log.info("tarotCard:{}",tarotCard.getCardId());

            JSONArray list = (JSONArray)jo.get("keywords");
            tarotCardKeyWordRepository.saveAll(
                    list.stream().map(object->{
                                JSONObject jObject = (JSONObject)object;
                                return new TarotCardKeyWord(
                                        Integer.parseInt(jObject.get("keywordId").toString())
                                        ,tarotCard.getCardId()
                                        ,Boolean.parseBoolean(jObject.get("isReversed").toString())
                                        ,jObject.get("keyword").toString()
                                );
                            }
                    ).toList()
            );


        }
    }

    private void saveCategory(){
        tarotCardCategoryRepository.saveAll(new ArrayList<>(){{
            add(new TarotCardCategory('A',"사랑"));
            add(new TarotCardCategory('B',"커리어"));
            add(new TarotCardCategory('C',"금전"));
            add(new TarotCardCategory('D',"건강"));
            add(new TarotCardCategory('E',"공부"));
            add(new TarotCardCategory('F',"친구"));
            add(new TarotCardCategory('G',"가족"));
            add(new TarotCardCategory('Z',"기타"));
        }});
    }

    private void saveInterpretation(TarotCard tarotCard) throws IOException, ParseException {
        JSONParser parser = new JSONParser();
        ClassPathResource resource = new ClassPathResource("data/interpretation/"+tarotCard.getCardId()+".json");
        Reader reader = new FileReader(resource.getFile(), StandardCharsets.UTF_8);
        JSONObject jSONObject = (JSONObject) parser.parse(reader);

        JSONArray dataArray = (JSONArray)jSONObject.get("categories");
        List<TarotCardInterpretation> tarotCardCategorys = new ArrayList<>();

        log.info("#####dataArray:{}",dataArray.toString());

        for(Object obj : dataArray){
            JSONObject jo = (JSONObject)obj;
            char categoryCode = jo.get("categoryCode").toString().charAt(0);
//            JSONArray array = (JSONArray)jo.get("interpretationContents");
            JSONArray array = (JSONArray)jo.get("interpretations");

            for(Object obj2 : array){
                JSONObject jo2 = (JSONObject)obj2;
                boolean isReversed = Boolean.parseBoolean(jo2.get("isReversed").toString());
                JSONArray array2 = (JSONArray)jo2.get("interpretationContents");

                Object oo= jo2.get("interpretationContents");
                log.info("#####oo:{}",oo.toString());
                log.info("#####oo:{}",oo.getClass());

                for(Object obj3 : array2){
                    log.info("#####obj3:{}",obj3);
                    log.info("#####obj3:{}",obj3.toString());
                    tarotCardCategorys.add(new TarotCardInterpretation(
                            tarotCard.getCardId()
                            ,categoryCode
                            ,isReversed
                            ,obj3.toString()
                    ));
                }
            }
        }

        tarotCardInterpretationRepository.saveAll(tarotCardCategorys);
    }

    private void saveReading() throws IOException, ParseException {
        JSONParser parser = new JSONParser();
        ClassPathResource resource = new ClassPathResource("data/reading/readingMethod.json");
        Reader reader = new FileReader(resource.getFile(), StandardCharsets.UTF_8);
        JSONObject jSONObject = (JSONObject) parser.parse(reader);
        JSONArray dataArray = (JSONArray)jSONObject.get("tarotReadingByCardCount");
        log.info("dataArray:{}",dataArray);
        for(Object obj : dataArray){
            JSONObject jo = (JSONObject)obj;
            Integer cardCount = Integer.parseInt(jo.get("cardCount").toString());

            JSONArray dataArray2 = (JSONArray)jo.get("methods");
            log.info("dataArray2:{}",dataArray2);
            for(int i = 0; i < dataArray2.size(); i++){
                Object obj2 = dataArray2.get(i);
                JSONObject jo2 = (JSONObject)obj2;
                String methodName = jo2.get("name").toString();
                String description = jo2.get("description").toString();

                TarotCardReadingMethod tarotCardReadingMethod = tarotCardReadingMethodRepository.save(new TarotCardReadingMethod(
                         cardCount
                        ,i
                        ,methodName
                        ,description
                ));

                JSONArray dataArray3 = (JSONArray)jo2.get("positions");
                for(int j = 0; j < dataArray3.size(); j++){
                    Object obj3 = dataArray3.get(j);
                    TarotCardReadingMethodPosition tarotCardReadingMethodPosition = tarotCardReadingMethodPositionRepository.save(new TarotCardReadingMethodPosition(
                            tarotCardReadingMethod.getMethodId()
                            ,j
                            ,obj3.toString()
                    ));
                }
            }

        }

    }

}
