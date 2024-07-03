package com.tarot.tarot.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.Comment;

@Entity
@Getter
@Table(
        name="tarot_card_keyword",
        uniqueConstraints={
                @UniqueConstraint(
                        name="cardKeyWordConstraint",
                        columnNames={"card_id", "is_reversed", "keyword"}
                )
        }
)
@NoArgsConstructor
public class TarotCardKeyWord {
  @Id
  @NotNull
  @Column(name = "keyword_id", nullable = false)
//  @GeneratedValue(strategy = GenerationType.IDENTITY)
//  @GeneratedValue(strategy = GenerationType.AUTO)
  @Comment("키워드 아이디")
  private Integer keywordId;

  @NotNull
  @Column(name = "card_id", nullable = false)
  @Comment("카드 아이디")
  private Integer cardId;

  @NotNull
  @Column(name = "is_reversed", nullable = false)
  @Comment("역방향 여부")
  private Boolean isReversed;

  @NotNull
  @Column(name = "keyword", length = 30, nullable = false)
  @Comment("키워드")
  private String keyword;

  public TarotCardKeyWord(Integer keywordId, Integer cardId, Boolean isReversed, String keyword) {
    this.keywordId = keywordId;
    this.cardId = cardId;
    this.isReversed = isReversed;
    this.keyword = keyword;
  }

  @ManyToOne
  @JoinColumns({
          @JoinColumn(name = "card_id", referencedColumnName = "card_id", insertable = false, updatable = false)
  })
  private TarotCard tarotCard;

}