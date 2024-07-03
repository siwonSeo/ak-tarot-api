package com.tarot.tarot.repository;

import com.tarot.tarot.entity.TarotCardInterpretation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TarotCardInterpretationRepository extends JpaRepository<TarotCardInterpretation, Integer>{
}
