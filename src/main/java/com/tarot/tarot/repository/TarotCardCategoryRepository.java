package com.tarot.tarot.repository;

import com.tarot.tarot.entity.TarotCardCategory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TarotCardCategoryRepository extends JpaRepository<TarotCardCategory, Character>{
}
