# TCP Multi-Client Server with File Transfer & Toy RPC

Python의 `socket` 모듈을 사용해 구현한 **TCP 기반 멀티 클라이언트 서버**입니다.

기본 Echo Server에서 시작하여 다음 기능들을 단계적으로 확장 구현했습니다:

- Non-blocking I/O
- `selectors` 기반 다중 클라이언트 처리
- Length-Prefixed 메시지 프레이밍
- 파일 업로드 / 다운로드 + SHA-256 무결성 검증
- Toy RPC (Remote Procedure Call) 시스템

본 프로젝트는 **자동차 네트워크 플랫폼 회사 인턴십 1차 교육 과제**의 일환으로 진행되었습니다.

---

## 📌 Features

### 1️⃣ TCP Echo
- 클라이언트가 전송한 데이터를 그대로 반환
- Length-prefix 기반 메시지 처리

### 2️⃣ Multi-Client Handling
- `selectors` 기반 이벤트 루프
- Non-blocking 소켓 처리
- 다중 클라이언트 동시 처리 가능

### 3️⃣ Custom Application Protocol
- 4-byte Big Endian Length Prefix
- JSON Header + Binary Payload 구조
- Request / Response ID 매칭 지원

### 4️⃣ File Transfer
- 파일 업로드
- 파일 다운로드
- SHA-256 기반 무결성 검증

### 5️⃣ Toy RPC System
- 서버 함수 원격 호출
- 지원 메서드:
  - `ping`
  - `add`
  - `echo`
- Request ID 기반 응답 매칭