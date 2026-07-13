require('dotenv').config();

const express = require('express');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');

// 🔥 [추가된 진짜 방어 무기들]
const helmet = require('helmet'); // Group 3 방어 (웹 보안 헤더)
const rateLimit = require('express-rate-limit'); // Group 4 방어 (DDoS 차단)
const { body, validationResult } = require('express-validator'); // Group 2 방어 (입력값 정화)

const securityMiddleware = require('./middleware/security');

const app = express();

// ==========================================
// 🛡️ Group 3 방어: Helmet 장착 (XSS, 스니핑 방어용 HTTP 헤더 자동 세팅)
// (주의: 구글 캡차 외부 스크립트 허용을 위해 CSP 옵션은 잠시 꺼둡니다)
// ==========================================
app.use(helmet({
    contentSecurityPolicy: false, 
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, 'public')));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// 미들웨어에서 DB를 쓸 수 있게 앱에 등록
app.set('pool', pool);

// ==========================================
// 🛡️ Group 4 방어: 로그인 전용 트래픽 제어 (Rate Limit)
// 15분 동안 5번 이상 로그인 요청(성공/실패 포함) 시 IP 원천 차단
// ==========================================
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15분
  max: 5, 
  message: { 
      success: false, 
      action: 'BLOCK_IP', 
      message: "🚨 과도한 요청이 감지되었습니다. 15분 후 다시 시도해주세요." 
  }
});

// ==========================================
// 🛡️ Group 2 방어: 입력값 정화 미들웨어 (Sanitization)
// 아이디, 비밀번호 칸에 <script> 같은 해킹 코드가 들어오면 강제로 문자를 깨버림 (escape)
// ==========================================
const sanitizeInputs = [
    body('username').trim().escape(),
    body('password').trim().escape()
];


// --- 회원가입 라우터 (입력값 정화 장착) ---
app.post('/register', sanitizeInputs, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
      return res.status(400).send('잘못된 입력값이 포함되어 있습니다.');
  }

  const { username, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2)',
      [username, hashedPassword]
    );
    res.send('회원가입 성공');
  } catch (err) {
    console.error(err);
    res.status(500).send('에러 발생');
  }
});


// --- 로그인 라우터 (방어 무기 3종 세트 모두 장착!) ---
// 방어 순서: 1. Rate Limit(연타형 봇 차단) -> 2. Sanitization(해킹 텍스트 정화) -> 3. Security Engine(행동 기반 캡차 판정)
app.post('/login', loginLimiter, sanitizeInputs, securityMiddleware, async (req, res) => {
  
  // 정화 과정에서 이상한 값이 발견되었는지 확인
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
      return res.status(400).json({ 
          success: false, 
          action: 'BLOCK_REQUEST', 
          message: '허용되지 않는 특수문자가 포함되어 있습니다.' 
      });
  }

  const { username, password } = req.body;

  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE username=$1',
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, message: '아이디 없음' });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (match) {
      res.json({ success: true, message: '로그인 성공' });
    } else {
      res.status(401).json({ success: false, message: '비밀번호 틀림' });
    }

  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: '에러 발생' });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`서버 실행중: http://localhost:${PORT}`);
});