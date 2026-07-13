// 회원가입 로직은 기존과 동일하게 유지합니다.
document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = document.getElementById('registerUsername').value;
    const password = document.getElementById('registerPassword').value;

    const response = await fetch('/register', {
        method:'POST',
        headers:{
            'Content-Type':'application/json'
        },
        body:JSON.stringify({
            username,
            password
        })
    });

    alert(await response.text());
});

// 로그인 로직에 FDS(보안 센서) 데이터를 추가합니다.
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;

    // 🔥 핵심 추가: fingerprint.js에서 수집한 징후 데이터를 가져옵니다.
    // (이 코드가 작동하려면 index.html에 <script src="fingerprint.js"></script>가 추가되어 있어야 합니다.)
    let securitySignals = {};
    if (typeof window.collectSecurityData === 'function') {
        securitySignals = window.collectSecurityData();
    }

    const response = await fetch('/login',{
        method:'POST',
        headers:{
            'Content-Type':'application/json'
        },
        body:JSON.stringify({
            username,
            password,
            signals: securitySignals // 🔥 아이디, 비번과 함께 몰래 묶어서 보냅니다.
        })
    });

    // 서버 응답 처리 (이후 백엔드에서 JSON 형태로 보안 판정 결과를 보내줄 예정입니다)
    try {
        const result = await response.json();
        
        // 보안 엔진이 위험을 감지하고 차단 액션을 보냈을 때의 처리
        if (result.action === 'REQUIRE_CAPTCHA') {
            alert("🚨 비정상적인 접근 감지: 캡차 인증이 필요합니다.");
        } else if (result.action === 'BLOCK_IP' || result.action === 'BLOCK_REQUEST') {
            alert("🚨 보안 정책에 의해 요청이 차단되었습니다.");
        } else {
            // 정상 처리 시 (성공 혹은 단순 비밀번호 틀림)
            alert(result.message || "로그인 처리 완료");
        }
    } catch (err) {
        // 서버가 아직 JSON 형태가 아닌 일반 텍스트를 반환할 때를 대비한 예외 처리
        alert("응답 완료 (서버 백엔드 업데이트 필요)");
    }
});