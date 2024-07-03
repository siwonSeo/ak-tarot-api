package com.tarot.common.service;

import com.tarot.tarot.dto.response.ResponseTarotCardConsult;
import com.tarot.tarot.service.TarotService;
import com.tarot.user.entity.UserBaseInterpretation;
import com.tarot.user.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;

import java.util.List;

@Slf4j
@RequiredArgsConstructor
@Service
public class UserTarotService {
    private final UserService userService;
    private final TarotService tarotService;

    public List<ResponseTarotCardConsult> getConsult(Integer consultId) {
        UserBaseInterpretation userBaseInterpretatio = userService.getUserBaseInterpretation(consultId);

        return tarotService.getTaroCardConsultsByCards(userBaseInterpretatio.getSearchCards());
    }
}
