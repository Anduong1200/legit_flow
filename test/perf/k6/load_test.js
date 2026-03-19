import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const detectionLatency = new Trend('detection_latency');

// Test configuration
export const options = {
  scenarios: {
    // Smoke test
    smoke: {
      executor: 'constant-vus',
      vus: 5,
      duration: '30s',
      startTime: '0s',
    },
    // Load test
    load: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '1m', target: 50 },
        { duration: '3m', target: 50 },
        { duration: '1m', target: 100 },
        { duration: '3m', target: 100 },
        { duration: '1m', target: 0 },
      ],
      startTime: '30s',
    },
  },
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<1000'],  // p95 < 500ms, p99 < 1s
    errors: ['rate<0.01'],                             // error rate < 1%
  },
};

const GATEWAY_URL = __ENV.GATEWAY_URL || 'http://localhost:8080';

// Test payloads — mix of clean and PII-containing requests
const payloads = [
  // Clean
  { prompt: 'Hôm nay thời tiết đẹp, hãy cho tôi biết dự báo thời tiết Hà Nội.' },
  { prompt: 'Cách nấu phở bò Hà Nội ngon nhất?' },
  // Contains VN phone
  { prompt: 'Liên hệ SĐT 0912345678 để biết thêm thông tin.' },
  // Contains CCCD
  { prompt: 'Khách hàng có CCCD 001234567890 cần hỗ trợ.' },
  // Contains email
  { prompt: 'Gửi báo cáo tới manager@company.com.vn trước 5pm.' },
  // Contains API key
  { prompt: 'Config: api_key=sk-abc123def456ghi789jkl012mno345pqr678' },
];

export default function () {
  const payload = payloads[Math.floor(Math.random() * payloads.length)];

  const res = http.post(
    `${GATEWAY_URL}/v1/chat/completions`,
    JSON.stringify(payload),
    {
      headers: {
        'Content-Type': 'application/json',
        'X-User-ID': `k6-user-${__VU}`,
      },
    }
  );

  const success = check(res, {
    'status is 200 or 403': (r) => r.status === 200 || r.status === 403,
    'response has body': (r) => r.body.length > 0,
    'has request ID': (r) => r.headers['X-Request-Id'] !== undefined || r.status === 200,
  });

  errorRate.add(!success);
  detectionLatency.add(res.timings.duration);

  sleep(0.1 + Math.random() * 0.3);
}
