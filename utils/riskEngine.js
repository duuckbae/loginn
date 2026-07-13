// utils/riskEngine.js

class RiskEngine {
  /**
   * @param {Object} signals - 프론트엔드 및 미들웨어에서 수집한 14가지 징후 (true/false)
   */
  constructor(signals = {}) {
    // 1단계: 수집된 14가지 징후 리스트 ON/OFF 판별 및 매핑
    this.signals = {
      isNewDevice: !!signals.isNewDevice,                 // 1. 새 기기/브라우저
      isNewIpRange: !!signals.isNewIpRange,               // 2. 처음 보는 IP 대역
      isAbnormalGeolocation: !!signals.isAbnormalGeolocation, // 3. 지리적 이동 속도 이상
      highVelocity: !!signals.highVelocity,               // 4. 단시간 내 연속 로그인 실패
      abnormalTime: !!signals.abnormalTime,               // 5. 주로 접속하던 시간대 외 접근
      noImageCss: !!signals.noImageCss,                   // 6. 이미지/CSS 미로딩
      noMouse: !!signals.noMouse,                         // 7. 마우스 이벤트 전혀 없음 (인간 불가능)
      tooManySessions: !!signals.tooManySessions,         // 8. 단일 IP 과도한 TCP 세션
      isShortStay: !!signals.isShortStay,                 // 9. 로그인 페이지 머문 시간 0.1초 미만 (인간 불가능)
      isBlacklistIp: !!signals.isBlacklistIp,             // 10. 악성 IP 리스트 포함 (Blacklist)
      isProxyVpn: !!signals.isProxyVpn,                   // 11. 익명 프록시, VPN, Tor 사용
      constantTyping: !!signals.constantTyping,           // 12. 키보드 입력 속도가 비정상적으로 일정함 (봇)
      multiAccountSingleIp: !!signals.multiAccountSingleIp, // 13. 단일 IP/기기에서 다중 계정 시도
      suddenPaste: !!signals.suddenPaste                  // 14. 타이핑 이벤트 없는 급격한 입력 (붙여넣기 오남용)
    };

    // 2단계: 4대 방어 그룹 점수 바구니 초기화
    this.scores = {
      Group1: 0, // 로그인 보호 (무차별 대입 4종, Credential Stuffing)
      Group2: 0, // 입력값 검증 (SQL Injection, 파라미터 및 응답 변조)
      Group3: 0, // 웹 요청/출력 보호 (XSS, CSRF)
      Group4: 0  // 트래픽 제어 (DDoS)
    };

    // 3단계: 기계적 징후 배율 변수 초기화
    this.botMultiplier = 1.0;
    this.CRITICAL_SCORE = 40; // 방어선 기준 점수
  }

  // 2단계: 그룹별 덧셈 계산 (기획하신 가중치 순위 반영)
  calculateBaseScores() {
    // 1. Device Fingerprint / User-Agent 변동
    if (this.signals.isNewDevice) {
      this.scores.Group1 += 25; // Credential Stuffing(Group1) 비중 높음
    }
    // 2. IP / ASN 주소 이상
    if (this.signals.isNewIpRange) {
      this.scores.Group4 += 30; // DDoS 계열 비중 높음
      this.scores.Group1 += 20; // Credential Stuffing 비중
    }
    // 3. Geolocation 이상 (물리적 불가능 이동)
    if (this.signals.isAbnormalGeolocation) {
      this.scores.Group1 += 35; // 해외 봇 로그인 타깃
    }
    // 4. Login Velocity 이상
    if (this.signals.highVelocity) {
      this.scores.Group1 += 35; // Brute Force 핵심 정황
    }
    // 5. 비정상적인 시간대 접근
    if (this.signals.abnormalTime) {
      this.scores.Group1 += 15;
      this.scores.Group4 += 15;
    }
    // 6. 정적 자원 미로딩
    if (this.signals.noImageCss) {
      this.scores.Group1 += 30; // 봇 대량 대입 API 호출
      this.scores.Group4 += 25; // DDoS
    }
    // 8. 과도한 TCP 세션 발생
    if (this.signals.tooManySessions) {
      this.scores.Group4 += 35; // DDoS의 본질
      this.scores.Group1 += 25; 
      this.scores.Group2 += 20; // SQLi 연속 주입
      this.scores.Group3 += 15; // XSS
    }
    // 10. 악성 IP 리스트 포함
    if (this.signals.isBlacklistIp) {
      this.scores.Group4 += 35;
      this.scores.Group1 += 25;
      this.scores.Group2 += 25;
      this.scores.Group3 += 20;
    }
    // 11. 익명 네트워크 사용 (VPN 등)
    if (this.signals.isProxyVpn) {
      this.scores.Group1 += 35; // 우회 대입 타깃
      this.scores.Group4 += 20;
    }
    // 13. 단일 기기 다중 계정 시도
    if (this.signals.multiAccountSingleIp) {
      this.scores.Group1 += 35; // Password Spraying, Reverse Brute Force
    }
    // 14. 붙여넣기 오남용
    if (this.signals.suddenPaste) {
      this.scores.Group1 += 20;
      this.scores.Group2 += 20; // SQLi 폼 주입
    }
  }

  // 3단계: 곱셈 팩터 연산 (인간 불가능 징후 발견 시 봇 기반 공격 가중치 폭발)
  applyMultipliers() {
    // 마우스 없음 발견 -> 배율 증가
    if (this.signals.noMouse) {
      this.botMultiplier *= 1.5;
    }
    // 0.1초 미만 체류 발견 -> 배율 증가
    if (this.signals.isShortStay) {
      this.botMultiplier *= 1.5;
    }
    // 일정한 타이핑 속도 발견 -> 배율 증가
    if (this.signals.constantTyping) {
      this.botMultiplier *= 1.3;
    }

    // 기계(봇) 기반 공격 모듈 점수에 최종 배율 곱하기 (Group 1과 Group 4가 주 타깃)
    if (this.botMultiplier > 1.0) {
      this.scores.Group1 = Math.round(this.scores.Group1 * this.botMultiplier * 10) / 10;
      this.scores.Group4 = Math.round(this.scores.Group4 * this.botMultiplier * 10) / 10;
      // 자동화 툴 스캐너 가능성이 있는 Group 2도 보너스 배율 적용 (*1.2)
      this.scores.Group2 = Math.round(this.scores.Group2 * 1.2 * 10) / 10;
    }
  }

  // 4단계 & 5단계: 최종 점수 비교 및 가장 적합한 방어 모듈 매핑
  determineAction() {
    let highestGroup = 'Safe';
    let maxScore = 0;

    // 가장 점수가 높은 그룹 추출
    for (const [group, score] of Object.entries(this.scores)) {
      if (score > maxScore) {
        maxScore = score;
        highestGroup = group;
      }
    }

    // 위험도 판정: 최고 점수가 기준선(40점)을 넘겼는지 확인
    const isDangerous = maxScore >= this.CRITICAL_SCORE;

    // 공격 종류(그룹)에 따른 맞춤형 방어 액션 확정
    let action = 'PASS';
    if (isDangerous) {
      if (highestGroup === 'Group1') action = 'REQUIRE_CAPTCHA'; // 캡차 및 계정 잠금 작동
      if (highestGroup === 'Group2') action = 'BLOCK_REQUEST';   // 입력값 거부 및 400 에러
      if (highestGroup === 'Group3') action = 'INVALIDATE_TOKEN'; // CSRF/XSS 차단 및 거부
      if (highestGroup === 'Group4') action = 'BLOCK_IP';         // 트래픽 제어 및 IP 임시 차단
    }

    return {
      isDangerous,
      highestGroup,
      maxScore,
      action,
      scoreTable: this.scores
    };
  }

  // 분석 실행기
  analyze() {
    this.calculateBaseScores();
    this.applyMultipliers();
    return this.determineAction();
  }
}

module.exports = RiskEngine;