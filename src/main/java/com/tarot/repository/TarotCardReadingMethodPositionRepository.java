package com.tarot.repository;

import com.tarot.entity.tarot.TarotCardReadingMethodPosition;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TarotCardReadingMethodPositionRepository extends JpaRepository<TarotCardReadingMethodPosition, Integer>{
}
