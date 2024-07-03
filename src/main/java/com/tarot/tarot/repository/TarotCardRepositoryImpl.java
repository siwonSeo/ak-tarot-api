package com.tarot.tarot.repository;

import com.querydsl.core.Tuple;
import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.core.types.dsl.Expressions;
import com.querydsl.core.types.dsl.StringExpression;
import com.querydsl.jpa.impl.JPAQuery;
import com.querydsl.jpa.impl.JPAQueryFactory;
import com.tarot.tarot.dto.request.RequestTarotCard;
import com.tarot.tarot.dto.response.*;
import com.tarot.tarot.entity.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.*;
import java.util.stream.Collectors;

import static com.querydsl.core.group.GroupBy.groupBy;
import static com.querydsl.core.group.GroupBy.list;
import static com.querydsl.core.types.Projections.constructor;

@RequiredArgsConstructor
@Repository
public class TarotCardRepositoryImpl implements TarotCardRepositoryCustom{
    private final JPAQueryFactory queryFactory;
    QTarotCard tarotCard = QTarotCard.tarotCard;
    QTarotCardKeyWord tarotCardKeyWord = QTarotCardKeyWord.tarotCardKeyWord;
    QTarotCardCategory tarotCardCategory = QTarotCardCategory.tarotCardCategory;
    QTarotCardInterpretation tarotCardInterpretation = QTarotCardInterpretation.tarotCardInterpretation;

    QTarotCardReadingMethod tarotCardReadingMethod = QTarotCardReadingMethod.tarotCardReadingMethod;
    QTarotCardReadingMethodPosition tarotCardReadingMethodPosition = QTarotCardReadingMethodPosition.tarotCardReadingMethodPosition;

    @Override
    public ResponseTarotCardKeyword findTaroCardByCardId(int reqCardId){
        List<Tuple> results = queryFactory
                .select(tarotCard.cardId,
                        tarotCard.cardNumber,
                        tarotCard.cardNumberName,
                        tarotCard.cardType,
                        tarotCard.cardName,
                        tarotCardKeyWord.keywordId,
                        tarotCardKeyWord.isReversed,
                        tarotCardKeyWord.keyword
                ).from(tarotCardKeyWord)
                .join(tarotCardKeyWord.tarotCard,tarotCard)
                .where(tarotCard.cardId.eq(reqCardId))
                .fetch();

        Tuple tupleMain = results.getFirst();
        ResponseTarotCardKeyword card = new ResponseTarotCardKeyword(
                tupleMain.get(tarotCard.cardId),
                tupleMain.get(tarotCard.cardNumber),
                tupleMain.get(tarotCard.cardNumberName),
                tupleMain.get(tarotCard.cardType),
                tupleMain.get(tarotCard.cardName),
                new ArrayList<>(),
                new ArrayList<>()
        );

        for (Tuple tuple : results) {
            Integer keywordId = tuple.get(tarotCardKeyWord.keywordId);
            Boolean isReversed = tuple.get(tarotCardKeyWord.isReversed);
            String keyword = tuple.get(tarotCardKeyWord.keyword);

            ResponseTarotCardKeyword.KeywordInfo newCategory = new ResponseTarotCardKeyword.KeywordInfo(
                    keywordId,
                    keyword
            );

            if(!isReversed){
                card.forwardKeywords().add(newCategory);
            }else{
                card.reverseKeywords().add(newCategory);
            }
        }

        card.forwardKeywords().sort(Comparator.comparing(ResponseTarotCardKeyword.KeywordInfo::keywordId));
        card.reverseKeywords().sort(Comparator.comparing(ResponseTarotCardKeyword.KeywordInfo::keywordId));

        return card;
    }

    @Override
    public List<ResponseTarotCardRandom> findTaroCardRandom(){
        return queryFactory.select(
                constructor(ResponseTarotCardRandom.class
                    , tarotCard.cardId
                    , Expressions.booleanTemplate("rand() < 0.5")
                )
            )
            .from(tarotCard)
            .orderBy(Expressions.stringTemplate("rand()").asc()).fetch();
    }

    @Override
    public ResponseTarotCardReading findTaroCardReading(int cardCount){
        return this.getTarotCardReadings(this.tarotCardReading(cardCount)).getFirst();
    }

    @Override
    public List<ResponseTarotCardReading> findTaroCardReadings(){
        return this.getTarotCardReadings(this.tarotCardReadings()).stream()
                .sorted(Comparator.comparing(ResponseTarotCardReading::cardCount))
                .map(reading -> new ResponseTarotCardReading(
                        reading.cardCount(),
                        reading.methods().stream()
                                .sorted(Comparator.comparing(ResponseTarotCardReading.ReadingMethod::methodId)
                                        .thenComparing(ResponseTarotCardReading.ReadingMethod::methodOrder))
                                .collect(Collectors.toList())
                ))
                .toList();
    }

    private List<ResponseTarotCardReading> getTarotCardReadings(BooleanExpression be){
        StringExpression groupConcatExpression = Expressions.stringTemplate("group_concat({0})",
                tarotCardReadingMethodPosition.positionName
        ).as("positionsName");
        return queryFactory
                .select(tarotCardReadingMethod.cardCount,
                        tarotCardReadingMethod.methodId,
                        tarotCardReadingMethod.methodName,
                        tarotCardReadingMethod.methodOrder,
                        tarotCardReadingMethod.description,
                        groupConcatExpression
                )
                .from(tarotCardReadingMethodPosition)
                .join(tarotCardReadingMethodPosition.method, tarotCardReadingMethod)
                .where(be)
                .groupBy(
                        tarotCardReadingMethod.cardCount,
                        tarotCardReadingMethod.methodId,
                        tarotCardReadingMethod.methodName,
                        tarotCardReadingMethod.methodOrder,
                        tarotCardReadingMethod.description
                )
                .transform(groupBy(tarotCardReadingMethod.cardCount)
                        .list(
                                constructor(
                                        ResponseTarotCardReading.class,
                                        tarotCardReadingMethod.cardCount,
                                        list(constructor(ResponseTarotCardReading.ReadingMethod.class
                                                        ,tarotCardReadingMethod.methodId
                                                        ,tarotCardReadingMethod.methodName
                                                        ,tarotCardReadingMethod.methodOrder
                                                        ,tarotCardReadingMethod.description
                                                        ,groupConcatExpression
                                                )
                                        )
                                )
                        )).stream()
                .sorted(Comparator.comparing(ResponseTarotCardReading::cardCount))
                .map(reading -> new ResponseTarotCardReading(
                        reading.cardCount(),
                        reading.methods().stream()
                                .sorted(Comparator.comparing(ResponseTarotCardReading.ReadingMethod::methodId)
                                        .thenComparing(ResponseTarotCardReading.ReadingMethod::methodOrder))
                                .collect(Collectors.toList())
                ))
                .toList();
    }

    private BooleanExpression tarotCardReading(int cardCount){
        return tarotCardReadingMethod.cardCount.eq(cardCount);
    }

    private BooleanExpression tarotCardReadings(){
        return null;
    }




    @Override
    public ResponseTarotCardReadingMethod findTaroCardReadingMethod(int cardCount){
        JPAQuery<TarotCardReadingMethod> query = queryFactory.selectFrom(tarotCardReadingMethod)
                .where(tarotCardReadingMethod.cardCount.eq(cardCount));
        return this.getTarotCardReadingMethodTransform(query).getFirst();
    }

    @Override
    public List<ResponseTarotCardReadingMethod> findTaroCardReadingMethods(){
        JPAQuery<TarotCardReadingMethod> query = queryFactory.selectFrom(tarotCardReadingMethod)
                .orderBy(tarotCardReadingMethod.cardCount.asc(), tarotCardReadingMethod.methodOrder.asc());
        return this.getTarotCardReadingMethodTransform(query);
    }

    private List<ResponseTarotCardReadingMethod> getTarotCardReadingMethodTransform(JPAQuery<TarotCardReadingMethod> query){
        return query.transform(groupBy(tarotCardReadingMethod.cardCount)
                .list(
                        constructor(
                                ResponseTarotCardReadingMethod.class,
                                tarotCardReadingMethod.cardCount,
                                list(constructor(ResponseTarotCardReadingMethod.ReadingMethod.class
                                                ,tarotCardReadingMethod.methodId
                                                ,tarotCardReadingMethod.methodName
                                                ,tarotCardReadingMethod.methodOrder
                                                ,tarotCardReadingMethod.description
                                        )
                                )
                        )
            )
        );
    }

    @Override
    public List<ResponseTarotCard> findTaroCardKewords(List<RequestTarotCard.TarotCardSearch> params){
        JPAQuery<TarotCardKeyWord> query =
                queryFactory.selectFrom(tarotCardKeyWord)
                        .join(tarotCardKeyWord.tarotCard,tarotCard)
                        .where(eqCardKeyWords(params))
                ;
        return query.transform(groupBy(tarotCardKeyWord.cardId)
                .list(
                        constructor(
                                ResponseTarotCard.class,
                                tarotCard.cardId,
                                tarotCard.cardNumber,
                                tarotCard.cardNumberName,
                                tarotCard.cardType,
                                tarotCard.cardName,
                                list(constructor(ResponseTarotCard.KeywordInfo.class
                                        ,tarotCardKeyWord.keywordId
                                        ,tarotCardKeyWord.isReversed
                                        ,tarotCardKeyWord.keyword)
                                )
                        )
                )
        );
    }

    @Override
    public List<ResponseTarotCardIntro> findTaroCardsIntro(){
        JPAQuery<TarotCard> query =
            queryFactory.selectFrom(tarotCard)
            ;
        return query.transform(groupBy(tarotCard.cardType)
                    .list(
                        constructor(
                                ResponseTarotCardIntro.class,
                                tarotCard.cardType,
                                list(constructor(ResponseTarotCardIntro.CardInfo.class
                                        ,tarotCard.cardId
                                        ,tarotCard.cardNumber
                                        ,tarotCard.cardNumberName
                                        ,tarotCard.cardName)
                                )
                        )
                    )
                );
    }



    @Override
    public List<ResponseTarotCardConsult> findTaroCardConsults(List<RequestTarotCard.TarotCardSearch> params){
        JPAQuery<TarotCardInterpretation> query =
                queryFactory.selectFrom(tarotCardInterpretation)
                        .join(tarotCardInterpretation.tarotCard,tarotCard)
                        .join(tarotCardCategory).on(tarotCardCategory.categoryCode.eq(tarotCardInterpretation.categoryCode))
                        .where(eqCardConsult(params))
                ;
        return query.transform(groupBy(tarotCardInterpretation.cardId)
                .list(
                        constructor(
                                ResponseTarotCardConsult.class,
                                tarotCardInterpretation.cardId,
                                tarotCard.cardNumber,
                                tarotCard.cardNumberName,
                                tarotCard.cardType,
                                tarotCard.cardName,
                                tarotCardInterpretation.isReversed,
                                list(constructor(String.class
                                        ,tarotCardInterpretation.content)
                                )
                        )
                )
        );
    }

    @Override
    public List<ResponseTarotCardInterpretation> findTaroCardInterpretations(List<RequestTarotCard.TarotCardSearch> params) {
        List<Tuple> results = queryFactory
                .select(tarotCard.cardId,
                        tarotCard.cardNumber,
                        tarotCard.cardNumberName,
                        tarotCard.cardType,
                        tarotCard.cardName,
                        tarotCardInterpretation.categoryCode,
                        tarotCardCategory.categoryName,
                        tarotCardInterpretation.isReversed,
                        tarotCardInterpretation.content)
                .from(tarotCardInterpretation)
                .join(tarotCardInterpretation.tarotCard, tarotCard)
                .join(tarotCardCategory).on(tarotCardCategory.categoryCode.eq(tarotCardInterpretation.categoryCode))
                .where(eqCardInterpretations(params))
                .fetch();

        Map<Integer, ResponseTarotCardInterpretation> cardMap = new HashMap<>();

        for (Tuple tuple : results) {
            Integer cardId = tuple.get(tarotCard.cardId);
            ResponseTarotCardInterpretation card = cardMap.computeIfAbsent(cardId,
                    k -> new ResponseTarotCardInterpretation(
                            cardId,
                            tuple.get(tarotCard.cardNumber),
                            tuple.get(tarotCard.cardNumberName),
                            tuple.get(tarotCard.cardType),
                            tuple.get(tarotCard.cardName),
                            new ArrayList<>()
                    )
            );

            char categoryCode = tuple.get(tarotCardInterpretation.categoryCode);
            String categoryName = tuple.get(tarotCardCategory.categoryName);
            boolean isReversed = tuple.get(tarotCardInterpretation.isReversed);
            String content = tuple.get(tarotCardInterpretation.content);

            ResponseTarotCardInterpretation.Category category = card.categories().stream()
                    .filter(c -> c.categoryCode() == categoryCode)
                    .findFirst()
                    .orElseGet(() -> {
                        ResponseTarotCardInterpretation.Category newCategory = new ResponseTarotCardInterpretation.Category(
                                categoryCode,
                                categoryName,
                                new ArrayList<>()
                        );
                        card.categories().add(newCategory);
                        return newCategory;
                    });

            ResponseTarotCardInterpretation.Category.Interpretation interpretation = category.interpretations().stream()
                    .filter(i -> i.isReversed() == isReversed)
                    .findFirst()
                    .orElseGet(() -> {
                        ResponseTarotCardInterpretation.Category.Interpretation newInterpretation = new ResponseTarotCardInterpretation.Category.Interpretation(
                                isReversed,
                                new ArrayList<>()
                        );
                        category.interpretations().add(newInterpretation);
                        return newInterpretation;
                    });

            interpretation.contents().add(content);
        }

        List<ResponseTarotCardInterpretation> finalResult = new ArrayList<>(cardMap.values());

        return finalResult;


    }

    private BooleanExpression eqCardConsult(List<RequestTarotCard.TarotCardSearch> params){
        return params.stream()
                .map(p->tarotCardInterpretation.cardId.eq(p.cardId()).and(tarotCardInterpretation.isReversed.eq(p.isReversed())).and(tarotCardInterpretation.categoryCode.eq(p.categoryCode())))
                .reduce(BooleanExpression::or)
                .orElseGet(tarotCardInterpretation.cardId::isNull);
    }

    private BooleanExpression eqCardKeyWords(List<RequestTarotCard.TarotCardSearch> params){
        return params.stream()
                .map(p->tarotCardKeyWord.cardId.eq(p.cardId()).and(tarotCardKeyWord.isReversed.eq(p.isReversed())))
                .reduce(BooleanExpression::or)
                .orElseGet(tarotCardKeyWord.cardId::isNull);
    }
    private BooleanExpression eqCardInterpretations(List<RequestTarotCard.TarotCardSearch> params){
        return params.stream()
                .map(p->{
                        BooleanExpression be = tarotCardInterpretation.cardId.eq(p.cardId());
                        if(p.isReversed() != null){
                            be = be.and(tarotCardInterpretation.isReversed.eq(p.isReversed()));
                        }
                        if(p.categoryCode() != null){
                            be = be.and(tarotCardInterpretation.categoryCode.eq(p.categoryCode()));
                        }
//                        return be.and(tarotCardInterpretation.isReversed.eq(p.isReversed()));
                        return be;
                    }
                )
//                .map(p->tarotCardInterpretation.cardId.eq(p.cardId()))
                .reduce(BooleanExpression::or)
                .orElseGet(tarotCardInterpretation.cardId::isNull);
    }
}
