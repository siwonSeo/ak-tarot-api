package com.tarot.user.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.Comment;

@Entity
@Getter
@Table(
        name="user_base",
        uniqueConstraints={
                @UniqueConstraint(
                        name="userConstraint",
                        columnNames={"email"}
                )
        }
)
@NoArgsConstructor
public class UserBase {
  @Id
  @NotNull
  @Column(name = "id", nullable = false)
  @GeneratedValue(strategy = GenerationType.AUTO)
  @Comment("유저 아이디")
  private Integer id;

  @NotNull
  @Column(name = "email", nullable = false)
  @Comment("이메일")
  private String email;

  @NotNull
  @Column(name = "name", nullable = false)
  @Comment("이름")
  private String name;

  @NotNull
  @Column(name = "picture", nullable = false)
  @Comment("사진")
  private String picture;

  public UserBase(String email, String name, String picture) {
    this.email = email;
    this.name = name;
    this.picture = picture;
  }
}