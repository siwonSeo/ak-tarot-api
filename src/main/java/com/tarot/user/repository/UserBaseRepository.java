package com.tarot.user.repository;

import com.tarot.user.entity.UserBase;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserBaseRepository extends JpaRepository<UserBase, Integer> {
    Optional<UserBase> findByEmail(String email);
}
