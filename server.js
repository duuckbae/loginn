const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// public 폴더를 정적 폴더로 설정
app.use(express.static(path.join(__dirname, "public")));

// 메인 페이지 연결
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// 서버 실행
app.listen(PORT, () => {
  console.log(`서버 실행 중: http://localhost:${PORT}`);
});