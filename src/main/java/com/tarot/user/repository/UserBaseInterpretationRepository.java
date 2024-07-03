package com.tarot.user.repository;

import com.tarot.user.entity.UserBaseInterpretation;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserBaseInterpretationRepository extends JpaRepository<UserBaseInterpretation, Integer> {
    Page<UserBaseInterpretation> findByUserId(Integer userId, Pageable pageable);
    UserBaseInterpretation findByUserIdAndId(Integer userId, Integer id);
}
