const express = require('express');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const path = require('path');
const securityMiddleware = require('./middleware/security');

const app = express();
const PORT = process.env.PORT || 3000;

// Supabase PostgreSQL 연결 설정
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});
app.set('pool', pool);

// ==========================================
// 🛡️ Group 3 방어: 웹 요청 보호 (Helmet 보안 헤더)
// ==========================================
app.use(helmet({
    contentSecurityPolicy: false // 테스트 및 외부 스크립트(구글 캡차) 로드를 위해 CSP는 잠시 완화
}));

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// 🛡️ Group 4 방어: 트래픽 제어 (Rate Limit - 광클 제한)
// ==========================================
const loginLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 차단 시간: 5분
    max: 5, // 5분 동안 최대 5번 허용
    handler: async (req, res) => {
        const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '0.0.0.0';
        
        // Supabase에 Group 4 차단 로그 실시간 기록
        try {
            await pool.query(
                `INSERT INTO security_logs (ip_address, target_id, risk_score, detected_group) 
                 VALUES ($1, $2, $3, $4)`,
                [clientIp, req.body.username || 'unknown_bot', 100, 'Group 4 (DDoS)']
            );
        } catch (err) {
            console.error('⚠️ Group 4 로그 저장 실패:', err);
        }

        res.status(429).json({ 
            success: false, 
            action: 'BLOCK_IP', 
            message: "🚨 과도한 요청이 감지되었습니다. 5분 후 다시 시도해주세요." 
        });
    }
});

// ==========================================
// 🛡️ Group 2 방어: 입력값 검증 및 차단 (Validation)
// ==========================================
const sanitizeInputs = [
    // 1. 아이디는 영문, 숫자, 언더바(_)만 허용! (그 외 특수문자, 공백 등 검찰관이 즉시 차단)
    body('username')
        .trim()
        .matches(/^[a-zA-Z0-9_]+$/)
        .withMessage('허용되지 않는 특수문자가 포함되어 있습니다.'),
    
    // 2. 비밀번호는 자유롭게 쓰되, 해킹용 우회 문자(< > ' " ; -)가 들어오면 즉시 에러 발생
    body('password')
        .trim()
        .custom(value => {
            if (/[<>'";\-]/.test(value)) {
                throw new Error('허용되지 않는 특수문자가 포함되어 있습니다.');
            }
            return true;
        })
];

// ==========================================
// 📝 [API] 회원가입 라우터 (기존 동일)
// ==========================================
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send('아이디와 비밀번호를 입력해주세요.');
    }

    try {
        const userExists = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (userExists.rows.length > 0) {
            return res.status(400).send('이미 존재하는 아이디입니다.');
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashedPassword]);

        res.status(201).send('회원가입 성공! 🎉');
    } catch (err) {
        console.error(err);
        res.status(500).send('회원가입 중 서버 오류가 발생했습니다.');
    }
});

// ==========================================
// 🔑 [API] 로그인 라우터 (보안 레이어 결합)
// ==========================================
app.post('/login', loginLimiter, sanitizeInputs, securityMiddleware, async (req, res) => {
    
    // 🔥 Group 2 검증 결과 확인: 이상한 텍스트 기입 시 여기서 에러 감지
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '0.0.0.0';
        
        // Supabase에 Group 2 차단 로그 실시간 기록
        try {
            await pool.query(
                `INSERT INTO security_logs (ip_address, target_id, risk_score, detected_group) 
                 VALUES ($1, $2, $3, $4)`,
                [clientIp, req.body.username || 'malicious_user', 80, 'Group 2 (Injection)']
            );
        } catch (err) {
            console.error('⚠️ Group 2 로그 저장 실패:', err);
        }

        // 프론트엔드가 Alert 팝업을 띄울 수 있게 응답 반환
        return res.status(400).json({ 
            success: false, 
            action: 'BLOCK_REQUEST', 
            message: errors.array()[0].msg // "허용되지 않는 특수문자가 포함되어 있습니다."
        });
    }

    const { username, password } = req.body;

    try {
        // 안전하게 파라미터화된 쿼리로 유저 조회
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

        if (result.rows.length === 0) {
            return res.status(400).json({ success: false, message: '존재하지 않는 아이디입니다.' });
        }

        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).json({ success: false, message: '비밀번호가 일치하지 않습니다.' });
        }

        // 모든 방어벽과 인증을 통과한 최종 로그인 성공 응답
        res.status(200).json({ success: true, message: '로그인 성공!' });

    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: '로그인 처리 중 서버 오류가 발생했습니다.' });
    }
});

// 메인 페이지 라우팅
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`🚀 서버가 포트 ${PORT}에서 든든하게 작동 중입니다...`);
});