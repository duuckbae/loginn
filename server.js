require('dotenv').config();

const express = require('express');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');

// 🛡️ 1. 방금 만든 보안 미들웨어 불러오기
const securityMiddleware = require('./middleware/security');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, 'public')));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.set('pool', pool);

app.post('/register', async (req, res) => {
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

// 🛡️ 2. 로그인 라우터에 securityMiddleware 장착
// 이제 이 라우터로 들어오기 전에 미들웨어가 먼저 가로채서 봇인지 검사합니다.
app.post('/login', securityMiddleware, async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE username=$1',
      [username]
    );

    // 💡 3. 프론트엔드(script.js)가 JSON 응답을 기다리도록 수정했으므로, 
    // 서버 응답도 res.send() 대신 res.json()으로 맞춰줍니다.
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