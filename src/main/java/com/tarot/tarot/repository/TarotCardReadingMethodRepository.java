package com.tarot.tarot.repository;

import com.tarot.tarot.entity.TarotCardReadingMethod;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TarotCardReadingMethodRepository extends JpaRepository<TarotCardReadingMethod, Integer>{
}
