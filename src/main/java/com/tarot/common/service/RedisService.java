package com.tarot.common.service;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class RedisService {
    private final RedisTemplate<String, String> redisTemplate;
    public void setValue(String key, String Value, long millseconds){
        redisTemplate.opsForValue().set(
                key, Value, millseconds, TimeUnit.MILLISECONDS);
    }

    public String getValue(String key){
        return redisTemplate.opsForValue().get(key);
    }
}
