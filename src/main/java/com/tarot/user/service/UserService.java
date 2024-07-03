package com.tarot.user.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tarot.common.dto.CustomUserDetails;
import com.tarot.tarot.dto.request.RequestTarotCard;
import com.tarot.tarot.dto.response.ResponseUserTarotCardConsult;
import com.tarot.user.entity.UserBaseInterpretation;
import com.tarot.user.repository.UserBaseInterpretationRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;


@Slf4j
@RequiredArgsConstructor
@Service
public class UserService {
    private final UserBaseInterpretationRepository userBaseInterpretationRepository;
    private final ObjectMapper objectMapper; // Jackson ObjectMapper 주입


    @Transactional
    public void saveUserConsult(int cardCount , Boolean isReverseOn
            , Character categoryCode, List<RequestTarotCard.TarotCardSearch> params){
        try {
            CustomUserDetails customUserDetails = (CustomUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            log.info("UserService saveUserConsult:{}",customUserDetails);
            if(customUserDetails != null) {
                userBaseInterpretationRepository.save(new UserBaseInterpretation(
                        customUserDetails.getId()
                        , cardCount
                        , isReverseOn
                        , categoryCode
                        , params
                ));
            }
        }catch (Exception e){
            log.info("상담이력 저장 오류:{}",e.getMessage());
        }

    }

    public UserBaseInterpretation getUserBaseInterpretation(Integer consultId){
        CustomUserDetails customUserDetails = (CustomUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return userBaseInterpretationRepository.findByUserIdAndId(customUserDetails.getId(), consultId);
    }

    public Page<ResponseUserTarotCardConsult> getUserTarotCardConsults(Pageable pageable){
        CustomUserDetails customUserDetails = (CustomUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Page<UserBaseInterpretation> interpretations = userBaseInterpretationRepository.findByUserId(customUserDetails.getId(), pageable);

        return interpretations.map(entity->new ResponseUserTarotCardConsult(
                entity.getId(),
                entity.getUserId(),
                entity.getCardCount(),
                entity.getIsReverseOn(),
                entity.getCategoryCode(),
                entity.getCreatedAt(),
                entity.getSearchCards()
        ));
    }
}
