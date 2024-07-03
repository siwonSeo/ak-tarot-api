package com.tarot.common.dto;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

@Getter
@Setter
public class CustomUserDetails implements UserDetails {
  private Integer id;
  private String password;
  private String email;
  private String name;
  private String picture;
  private Collection<? extends GrantedAuthority> authorities;

  public CustomUserDetails(Integer id, String password, String email, String name, String picture, Collection<? extends GrantedAuthority> authorities) {
    this.id = id;
    this.password = password;
    this.email = email;
    this.name = name;
    this.picture = picture;
    this.authorities = authorities;
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return authorities;
  }

  @Override
  public String getPassword() {
    return password;
  }

  @Override
  public String getUsername() {
    return id.toString();
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }
}