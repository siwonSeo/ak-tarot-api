package com.tarot.tarot.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.Comment;

@Entity
@Getter
@Table(
        name="tarot_card_reading_method",
        uniqueConstraints={
                @UniqueConstraint(
                        name="readingMethodConstraint",
                        columnNames={"card_count", "method_order"}
                )
        }
)
@NoArgsConstructor
public class TarotCardReadingMethod {
  @Id
  @NotNull
  @Column(name = "method_id", nullable = false)
  @GeneratedValue(strategy = GenerationType.AUTO)
  @Comment("방법 아이디")
  private Integer methodId;

  @NotNull
  @Column(name = "card_count", nullable = false)
  @Comment("카드 갯수")
  private Integer cardCount;

  @NotNull
  @Column(name = "method_order", nullable = false)
  @Comment("방법 순서")
  private Integer methodOrder;

  @NotNull
  @Column(name = "method_name", length = 255, nullable = false)
  @Comment("방법명")
  private String methodName;

  @NotNull
  @Column(name = "description", length = 50, nullable = false, columnDefinition = "TEXT")
  @Comment("설명")
  private String description;

  public TarotCardReadingMethod(Integer cardCount, Integer methodOrder, String methodName, String description) {
    this.cardCount = cardCount;
    this.methodOrder = methodOrder;
    this.methodName = methodName;
    this.description = description;
  }

}