package com.tarot.user.controller;

import com.tarot.common.config.DisableSwaggerSecurity;
import com.tarot.common.service.UserTarotService;
import com.tarot.tarot.dto.response.ResponseTarotCardConsult;
import com.tarot.tarot.dto.response.ResponseUserTarotCardConsult;
import com.tarot.user.entity.UserBaseInterpretation;
import com.tarot.tarot.service.TarotService;
import com.tarot.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;

@RequiredArgsConstructor
@RequestMapping("/api/user")
@Controller
public class UserApiController {
    private final UserTarotService userTarotService;
    private final UserService userService;
    private final TarotService tarotService;

    @GetMapping("/card/consults")
    public ResponseEntity<Page<ResponseUserTarotCardConsult>> consults(@PageableDefault(page = 0, size = 10, sort = "createdAt", direction = Sort.Direction.DESC)Pageable pageable) {
        return new ResponseEntity<>(userService.getUserTarotCardConsults(pageable), HttpStatus.OK);
    }

    @DisableSwaggerSecurity
    @GetMapping("/card/consult/{consultId}")
    public ResponseEntity<List<ResponseTarotCardConsult>> consult(@PathVariable("consultId") Integer consultId) {
        return new ResponseEntity<>(userTarotService.getConsult(consultId), HttpStatus.OK);
    }

}
