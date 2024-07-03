package com.tarot.tarot.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.Comment;

@Entity
@Getter
@Table(
        name="tarot_card_interpretation"
)
@NoArgsConstructor
public class TarotCardInterpretation {
  @Id
  @NotNull
  @Column(name = "interpretation_id", nullable = false)
//  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @GeneratedValue(strategy = GenerationType.AUTO)
  @Comment("해석 아이디")
  private Integer interpretationId;

  @NotNull
  @Column(name = "card_id", nullable = false)
  @Comment("카드 아이디")
  private Integer cardId;

  @NotNull
  @Column(name = "is_reversed", nullable = false)
  @Comment("역방향 여부")
  private Boolean isReversed;

  @NotNull
  @Column(name = "category_code", nullable = false)
  @Comment("카테고리 코드")
  private Character categoryCode;

  @NotNull
  @Column(name = "content", nullable = false)
  @Comment("내용")
  private String content;

  public TarotCardInterpretation(Integer cardId, Character categoryCode, Boolean isReversed, String content) {
    this.cardId = cardId;
    this.categoryCode = categoryCode;
    this.isReversed = isReversed;
    this.content = content;
  }

  @ManyToOne
  @JoinColumns({
          @JoinColumn(name = "card_id", referencedColumnName = "card_id", insertable = false, updatable = false)
  })
  private TarotCard tarotCard;

  @OneToOne
  @JoinColumns({
          @JoinColumn(name = "category_code", referencedColumnName = "category_code", insertable = false, updatable = false)
  })
  private TarotCardCategory tarotCardCategory;

}