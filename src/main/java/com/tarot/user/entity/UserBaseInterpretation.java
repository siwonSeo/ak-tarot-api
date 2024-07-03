package com.tarot.user.entity;

import com.tarot.tarot.dto.request.RequestTarotCard;
import com.vladmihalcea.hibernate.type.json.JsonType;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.Comment;
import org.hibernate.annotations.Type;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Getter
@Table(
        name="user_base_interpretation"
)
@EntityListeners(AuditingEntityListener.class)
@NoArgsConstructor
public class UserBaseInterpretation {
  @Id
  @NotNull
  @Column(name = "id", nullable = false)
  @GeneratedValue(strategy = GenerationType.AUTO)
  @Comment("해설 아이디")
  private Integer id;

  @NotNull
  @Column(name = "user_id", nullable = false)
  @Comment("유저 ID")
  private Integer userId;

  @NotNull
  @Column(name = "card_count", nullable = false)
  @Comment("선택 카드 갯수")
  private Integer cardCount;

  @NotNull
  @Column(name = "is_reverse_on", nullable = false)
  @Comment("역방향 포함 여부")
  private Boolean isReverseOn;

  @NotNull
  @Column(name = "category_code", nullable = false)
  @Comment("카테고리 코드")
  private Character categoryCode;

  @Type(JsonType.class)
  @Column(name = "search_cards", nullable = false, columnDefinition = "json")
  private List<RequestTarotCard.TarotCardSearch> searchCards;

  public UserBaseInterpretation(Integer userId, Integer cardCount, Boolean isReverseOn, Character categoryCode, List<RequestTarotCard.TarotCardSearch> searchCards) {
    this.userId = userId;
    this.cardCount = cardCount;
    this.isReverseOn = isReverseOn;
    this.categoryCode = categoryCode;
    this.searchCards = searchCards;
  }

  @ManyToOne
  @JoinColumn(name = "user_id", referencedColumnName = "id", insertable = false, updatable = false)
  private UserBase userBase;

  @CreatedDate
  private LocalDateTime createdAt;
}