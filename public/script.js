// ========================================================
// 1. 회원가입 요청 로직 (기존 유지)
// ========================================================
document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = document.getElementById('registerUsername').value;
    const password = document.getElementById('registerPassword').value;

    const response = await fetch('/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            username,
            password
        })
    });

    alert(await response.text());
});

// ========================================================
// 2. 1차 로그인 시도 로직 (보안 센서 데이터 포함)
// ========================================================
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;

    // FDS(보안 센서) 데이터 수집
    let securitySignals = {};
    if (typeof window.collectSecurityData === 'function') {
        securitySignals = window.collectSecurityData();
    }

    const response = await fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            username,
            password,
            signals: securitySignals // 아이디, 비번과 함께 징후 데이터 전송
        })
    });

    try {
        const result = await response.json();
        
        // 🛡️ 리스크 엔진이 캡차 인증을 요구한 경우
        if (result.action === 'REQUIRE_CAPTCHA') {
            const captchaModal = document.getElementById('captchaModal');
            if (captchaModal) {
                captchaModal.style.display = 'block'; // 숨겨둔 진짜 구글 캡차 창 표시
            }
            document.getElementById('loginForm').style.display = 'none'; // 기존 로그인 폼은 숨김
            
        // 🛡️ IP 차단 등 완전 거부 정황인 경우
        } else if (result.action === 'BLOCK_IP' || result.action === 'BLOCK_REQUEST') {
            alert("🚨 보안 정책에 의해 요청이 차단되었습니다.");
        } else {
            // 정상적인 판정 처리 (성공 혹은 패스워드 불일치)
            if (result.success) {
                alert("로그인 성공! 🎉");
            } else {
                alert(result.message || "로그인 실패");
            }
        }
    } catch (err) {
        alert("서버 응답 오류가 발생했습니다.");
    }
});

// ========================================================
// 3. 2차 캡차 인증 후 로그인 재시도 로직 (추가된 핵심 무기)
// ========================================================
async function verifyCaptcha() {
    // 구글 캡차 인증 박스로부터 발급된 토큰 꺼내오기
    const token = grecaptcha.getResponse();
    
    if (!token) {
        alert("캡차 체크박스를 먼저 체크해 주세요!");
        return;
    }

    // 로그인 폼에 입력되어 있던 아이디와 비밀번호 재수집
    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;

    // 서버로 캡차 토큰을 얹어서 재인증 요청
    const response = await fetch('/login', {
        method: 'POST',
        headers: { 
            'Content-Type': 'application/json' 
        },
        body: JSON.stringify({
            username,
            password,
            captchaToken: token // 🔥 이 토큰이 실려가면 미들웨어가 구글과 대조합니다.
        })
    });

    try {
        const result = await response.json();

        if (result.success) {
            alert("로그인 성공! 🎉 보안 검증을 통과했습니다.");
            
            // 로그인 성공 후 원래 화면 상태로 복구
            document.getElementById('captchaModal').style.display = 'none';
            document.getElementById('loginForm').style.display = 'block';
            grecaptcha.reset(); // 캡차 상태 초기화
        } else {
            alert(result.message || "로그인 실패");
            grecaptcha.reset(); // 실패 시 캡차 재인증 유도
        }
    } catch (err) {
        alert("캡차 검증 서버 통신 중 에러가 발생했습니다.");
        grecaptcha.reset();
    }
}