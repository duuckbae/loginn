// public/fingerprint.js

// 서버로 보낼 징후 데이터 초기값 세팅 (프론트엔드에서 수집 가능한 항목들)
const clientSignals = {
  noMouse: true,            // 마우스 움직임이 없다고 가정하고 시작
  isShortStay: false,       // 0.1초 미만 체류 여부
  constantTyping: false,    // 기계적인 타이핑 여부
  suddenPaste: false,       // 붙여넣기 오남용 여부
  isNewDevice: false        // 새로운 기기 여부 (로컬 스토리지 활용)
};

// 측정용 변수들
const pageLoadTime = Date.now();
let keydownIntervals = [];
let lastKeydownTime = 0;
let keyPressCount = 0;

// 1. 마우스 움직임 감지 (한 번이라도 움직이면 봇이 아님을 증명)
document.addEventListener('mousemove', () => {
  clientSignals.noMouse = false;
}, { once: true }); // 한 번 감지되면 이벤트 리스너 해제 (메모리 최적화)

// 2. 키보드 타이핑 패턴 및 붙여넣기 감지
document.addEventListener('DOMContentLoaded', () => {
  // 처음 방문하는 기기인지 로컬 스토리지로 확인
  if (!localStorage.getItem('device_fingerprint_seen')) {
    clientSignals.isNewDevice = true;
  }

  const inputs = document.querySelectorAll('input');
  
  inputs.forEach(input => {
    // 키보드 누를 때마다 시간 간격 측정
    input.addEventListener('keydown', () => {
      const now = Date.now();
      if (lastKeydownTime > 0) {
        keydownIntervals.push(now - lastKeydownTime);
      }
      lastKeydownTime = now;
      keyPressCount++;
    });

    // 입력창에 값이 갑자기 변할 때 (붙여넣기 감지)
    input.addEventListener('input', (e) => {
      // 키보드를 거의 누르지 않았는데 긴 텍스트가 들어왔다면 스크립트 주입이나 봇의 붙여넣기로 의심
      if (e.target.value.length > 5 && keyPressCount < 2) {
        clientSignals.suddenPaste = true;
      }
    });
  });
});

// 3. 로그인 버튼을 누를 때 데이터를 포장해서 반환하는 함수
window.collectSecurityData = function() {
  // 체류 시간 계산 (0.1초 = 100ms 미만인지)
  const stayDuration = Date.now() - pageLoadTime;
  if (stayDuration < 100) {
    clientSignals.isShortStay = true;
  }

  // 기계적인 타이핑 감지 (입력 간격의 편차가 10ms 이하로 너무 일정하면 봇으로 간주)
  if (keydownIntervals.length > 4) {
    const isBotTyping = keydownIntervals.every((interval, index, arr) => {
      if (index === 0) return true;
      return Math.abs(interval - arr[index - 1]) < 10;
    });
    if (isBotTyping) clientSignals.constantTyping = true;
  }

  // 로그인 성공 시(또는 시도 시) 기기 방문 기록 남기기
  localStorage.setItem('device_fingerprint_seen', 'true');

  return clientSignals;
};