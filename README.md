## 개발환경
- Java 21
- spring boot (3.3.0)
- JPA
- Gradle
- H2
- Swagger

# A(ce)K(ing) Tarot
- 타로 카드별 키워드 소개
- 카드 뽑는 방법별 해설 소개
- 주제, 카드(장 수), 역방향 포함 여부,자동/수동 선택후 타로 해설을 제공합니다.
- AK-Tarot의 사용자 추가버전(구글 로그인)

## 사용 기술
<b>BE</b>
- Java 21
- Spring Boot
- Spring Data JPA
- Spring Security
- Lombok

<b>FE</b>
- HTML5/CSS
- JavaScript
- Thymeleaf

<b>Build Tool</b>
- Gradle

<b>DB</b>
- H2

## 데이터 구성
타로 카드(가장 보편적인 웨이트 타로)는 총 78장으로 구성되있으며 아래와 같이 구성되있습니다.
메이저 아르카나(22장)
마이나 아르카나(56장)
- 완드(14장)
- 컵(14장)
- 소드(14장)
- 펜타클(14장)

타로카드 해석에는 정방향/역방향에 따라 해석이 달라지므로 이 부분이 포함되있습니다.
-테이블 구성
카테고리(질문용)
타로카드
카드 키워드
카드 키워드별 해석

리딩 방식(타로카드 선택 장 수 별)
선택 위치별 해설키워드

사용자 정보
사용자 해설 이력 정보

## 구현 순서
초기 데이터 적재(H2 메모리 방식 사용시)
타임리프 화면을 통한 기능 구현
OAutnh로그인 적용(구글)
로그인후 카드점 실행시 이력적재
내가 뽑았던 카드! 에서 이력 조회

##초기 환경 변수 필요(구글 OAuth2 인증시 필요)
- google-client-id
- google-client-secret
- google-redirection-url