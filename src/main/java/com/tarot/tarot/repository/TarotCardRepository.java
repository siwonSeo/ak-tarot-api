package com.tarot.tarot.repository;

import com.tarot.tarot.entity.TarotCard;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TarotCardRepository extends JpaRepository<TarotCard, Integer>, TarotCardRepositoryCustom{
}
