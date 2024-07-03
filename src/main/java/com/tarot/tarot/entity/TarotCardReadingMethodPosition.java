package com.tarot.tarot.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.Comment;

@Entity
@Getter
@Table(
        name="tarot_card_reading_method_position",
        uniqueConstraints={
                @UniqueConstraint(
                        name="readingMethodPositionConstraint",
                        columnNames={"method_id", "position_order"}
                )
        }
)
@NoArgsConstructor
public class TarotCardReadingMethodPosition {
  @Id
  @NotNull
  @Column(name = "position_id", nullable = false)
  @GeneratedValue(strategy = GenerationType.AUTO)
  @Comment("위치 아이디")
  private Integer positionId;

  @NotNull
  @Column(name = "method_id", nullable = false)
  @Comment("방법 아이디")
  private Integer methodId;

  @NotNull
  @Column(name = "position_order", nullable = false)
  @Comment("위치 순서")
  private Integer positionOrder;

  @NotNull
  @Column(name = "position_name", nullable = false)
  @Comment("위치명")
  private String positionName;

  public TarotCardReadingMethodPosition(Integer methodId, Integer positionOrder, String positionName) {
    this.methodId = methodId;
    this.positionOrder = positionOrder;
    this.positionName = positionName;
  }

  @ManyToOne
  @JoinColumn(name = "method_id", referencedColumnName = "method_id", insertable = false, updatable = false)
  private TarotCardReadingMethod method;
}