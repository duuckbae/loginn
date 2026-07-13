// middleware/security.js
const RiskEngine = require('../utils/riskEngine');

// 💡 server.js에서 생성한 pool 인스턴스를 활용할 수 있도록 함수를 구성합니다.
// Express 미들웨어는 req 객체에 커스텀 프로퍼티를 심어서 상위 객체(pool 등)를 넘겨받는 것이 정석입니다.
async function securityMiddleware(req, res, next) {
    try {
        // 1. 요청 데이터 추출 (아이디, 비밀번호, 프론트엔드 징후 데이터)
        const { username, password, signals: clientSignals = {} } = req.body;
        
        // 접속자 IP 확인 (Render 같은 프록시 환경에서는 x-forwarded-for 헤더 확인이 필수적입니다)
        const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '0.0.0.0';

        // 2. 서버 측 탐지 징후(Server-side Signals) 수집
        const currentHour = new Date().getHours();
        
        const serverSignals = {
            // VPN/프록시 헤더 흔적 감지
            isProxyVpn: !!(req.headers['via'] || req.headers['x-forwarded-for']),
            
            // 자동화 공격이 자주 발생하는 심야/새벽 시간대 (새벽 2시 ~ 5시)
            abnormalTime: currentHour >= 2 && currentHour <= 5,
            
            // 💡 추후 확장 가능 영역 (이전 시도 이력 조회 필요 시)
            highVelocity: false,
            tooManySessions: false,
            isNewIpRange: false
        };

        // 3. 프론트엔드 행동 데이터와 서버의 네트워크 데이터 병합
        const finalSignals = { ...clientSignals, ...serverSignals };

        // 4. 리스크 엔진 가동 및 덧셈/곱셈 알고리즘 분석 수행
        const engine = new RiskEngine(finalSignals);
        const analysisResult = engine.analyze();

        // 💡 5. [FDS 실시간 기록] Supabase (PostgreSQL)의 security_logs 테이블에 로그 Insert
        // server.js에서 수신 대기 중인 pool 객체는 req.app.get('pool') 형태로 미들웨어에서 꺼내 쓸 수 있습니다.
        const pool = req.app.get('pool');
        if (pool) {
            // 비동기(Async) 쿼리 실행 - 로그 저장이 실패하더라도 전체 로그인 흐름이 깨지지 않도록 예외 처리 유의
            pool.query(
                `INSERT INTO security_logs (ip_address, target_id, risk_score, detected_group) 
                 VALUES ($1, $2, $3, $4)`,
                [clientIp, username || 'unknown', analysisResult.maxScore, analysisResult.highestGroup]
            ).catch(err => console.error('⚠️ 보안 로그 DB 저장 중 에러 발생:', err));
        }

        // 6. 엔진 분석 결과 기준 점수(40점) 이상 위험군 차단 제어
        if (analysisResult.isDangerous) {
            console.warn(`🚨 [보안 차단 안내] IP: ${clientIp} -> 탐지 그룹: ${analysisResult.highestGroup} (${analysisResult.maxScore}점)`);
            
            // 프론트엔드(script.js)에서 후속 처리할 수 있도록 JSON 포맷 및 403 Forbidden 리턴
            return res.status(403).json({
                success: false,
                action: analysisResult.action,
                message: "보안 정책에 의해 접근이 일시적으로 제한되었습니다."
            });
        }

        // 7. 안전 점수 통과 시 다음 로그인 로직(아이디/비번 대조)으로 요청 인계
        next();

    } catch (error) {
        console.error('⚠️ 미들웨어 내부 치명적 예외 발생:', error);
        // 보안 모듈 에러 시 안전을 위해 우선 통과 처리 (Fail-Open 모드)
        next();
    }
}

module.exports = securityMiddleware;