package com.tarot.repository;

import com.tarot.dto.response.ResponseUserTarotCardConsult;
import com.tarot.entity.user.UserBase;
import com.tarot.entity.user.UserBaseInterpretation;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserBaseInterpretationRepository extends JpaRepository<UserBaseInterpretation, Integer> {
    Page<UserBaseInterpretation> findByUserId(Integer userId, Pageable pageable);
    UserBaseInterpretation findByUserIdAndId(Integer userId, Integer id);
}
