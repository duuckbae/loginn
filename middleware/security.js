// middleware/security.js
const RiskEngine = require('../utils/riskEngine');
const axios = require('axios'); // 👈 구글 서버와 통신하기 위해 추가

async function securityMiddleware(req, res, next) {
    try {
        const { username, password, signals: clientSignals = {}, captchaToken } = req.body;
        const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '0.0.0.0';

        // ==========================================
        // 🔥 [1-3 핵심] 프론트에서 보낸 캡차 토큰이 있는 경우 (2차 검증 단계)
        // ==========================================
        if (captchaToken) {
            console.log(`🤖 캡차 토큰 검증 시작... IP: ${clientIp}`);
            
            // 구글 reCAPTCHA 검증 API로 요청을 보냅니다.
            const googleResponse = await axios.post(
                `https://www.google.com/recaptcha/api/siteverify`,
                null,
                {
                    params: {
                        secret: process.env.RECAPTCHA_SECRET_KEY, // 내 비밀키
                        response: captchaToken,                  // 프론트가 준 토큰
                        remoteip: clientIp                        // 사용자 IP
                    }
                }
            );

            // 구글이 "인증 성공!" 이라고 응답하면 통과시키고 진짜 로그인 로직(next)으로 보냅니다.
            if (googleResponse.data && googleResponse.data.success) {
                console.log(`✅ 캡차 인증 성공! 전방 압박 해제.`);
                return next(); 
            } else {
                console.warn(`❌ 캡차 인증 실패 또는 만료된 토큰.`);
                return res.status(403).json({
                    success: false,
                    action: 'REQUIRE_CAPTCHA',
                    message: "캡차 인증에 실패했습니다. 다시 시도해 주세요."
                });
            }
        }

        // ==========================================
        // 1차 일반 로그인 시도 시 (기존 리스크 엔진 로직)
        // ==========================================
        const currentHour = new Date().getHours();
        const serverSignals = {
            isProxyVpn: !!(req.headers['via'] || req.headers['x-forwarded-for']),
            abnormalTime: currentHour >= 2 && currentHour <= 5,
            highVelocity: false,
            tooManySessions: false,
            isNewIpRange: false
        };

        const finalSignals = { ...clientSignals, ...serverSignals };
        const engine = new RiskEngine(finalSignals);
        const analysisResult = engine.analyze();

        // 실시간 DB 로그 기록
        const pool = req.app.get('pool');
        if (pool) {
            pool.query(
                `INSERT INTO security_logs (ip_address, target_id, risk_score, detected_group) 
                 VALUES ($1, $2, $3, $4)`,
                [clientIp, username || 'unknown', analysisResult.maxScore, analysisResult.highestGroup]
            ).catch(err => console.error('⚠️ 보안 로그 DB 저장 중 에러 발생:', err));
        }

        // 40점 이상 위험군 발견 시 캡차 요구 뿜기
        if (analysisResult.isDangerous) {
            console.warn(`🚨 [보안 차단] IP: ${clientIp} -> ${analysisResult.highestGroup} (${analysisResult.maxScore}점)`);
            
            return res.status(403).json({
                success: false,
                action: analysisResult.action, // 'REQUIRE_CAPTCHA' 등
                message: "비정상적인 접근이 감지되었습니다. 캡차 인증이 필요합니다."
            });
        }

        // 안전 점수 통과 시 바로 패스
        next();

    } catch (error) {
        console.error('⚠️ 미들웨어 오류:', error);
        next();
    }
}

module.exports = securityMiddleware;