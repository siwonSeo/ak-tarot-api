package com.tarot.tarot.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.Comment;

@Entity
@Getter
@Table(
        name="tarot_card_category"
)
@NoArgsConstructor
public class TarotCardCategory {
  @Id
  @NotNull
  @Column(name = "category_code", nullable = false)
  @Comment("카테고리 코드")
  private Character categoryCode;

  @NotNull
  @Column(name = "category_name", nullable = false)
  @Comment("카테고리 명")
  private String categoryName;

  public TarotCardCategory(Character categoryCode, String categoryName) {
    this.categoryCode = categoryCode;
    this.categoryName = categoryName;
  }

}