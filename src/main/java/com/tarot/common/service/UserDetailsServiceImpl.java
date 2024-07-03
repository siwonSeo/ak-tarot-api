package com.tarot.common.service;

import com.tarot.common.dto.CustomUserDetails;
import com.tarot.common.code.ErrorStatusMessage;
import com.tarot.user.entity.UserBase;
import com.tarot.common.exception.ApiException;
import com.tarot.user.repository.UserBaseRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

@RequiredArgsConstructor
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

  private final UserBaseRepository userBaseRepository;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    UserBase user = userBaseRepository.findByEmail(username).orElseThrow(() -> new ApiException(ErrorStatusMessage.FORBIDDEN_USER));

    return new CustomUserDetails(
            user.getId(),
            "",
            user.getEmail(),
            user.getName(),
            user.getPicture(),
            Collections.emptyList());
  }
}
