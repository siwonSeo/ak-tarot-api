package com.tarot.tarot.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.Comment;

@Entity
@Getter
@Table(
        name="tarot_card",
        uniqueConstraints={
                @UniqueConstraint(
                        name="cardConstraint",
                        columnNames={"card_type", "card_number"}
                )
        }
)
@NoArgsConstructor
public class TarotCard {
  @Id
  @NotNull
  @Column(name = "card_id", nullable = false)
  @Comment("카드 아이디")
  private Integer cardId;

  @NotNull
  @Column(name = "card_number", nullable = false)
  @Comment("번호")
  private Integer cardNumber;

  @NotNull
  @Column(name = "card_number_name", length = 20, nullable = false)
  @Comment("번호명")
  private String cardNumberName;

  @NotNull
  @Column(name = "card_name", length = 50, nullable = false)
  @Comment("카드 이름")
  private String cardName;

  @NotNull
  @Column(name = "card_type", length = 10, nullable = false)
  @Comment("카드 타입")
  private String cardType;

  public TarotCard(Integer cardId, Integer cardNumber, String cardNumberName, String cardName, String cardType) {
    this.cardId = cardId;
    this.cardNumber = cardNumber;
    this.cardNumberName = cardNumberName;
    this.cardName = cardName;
    this.cardType = cardType;
  }
}