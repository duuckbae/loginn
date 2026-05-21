require('dotenv').config();

const express = require('express');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');

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

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE username=$1',
      [username]
    );

    if (result.rows.length === 0) {
      return res.send('아이디 없음');
    }

    const user = result.rows[0];

    const match = await bcrypt.compare(password, user.password);

    if (match) {
      res.send('로그인 성공');
    } else {
      res.send('비밀번호 틀림');
    }

  } catch (err) {
    console.error(err);
    res.status(500).send('에러 발생');
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`서버 실행중`);
});