package com.tarot.tarot.repository;

import com.tarot.tarot.entity.TarotCardKeyWord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TarotCardKeyWordRepository extends JpaRepository<TarotCardKeyWord, Integer>{
}
