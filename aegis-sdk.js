/**
 * AegisScan Telemetry SDK for Node.js
 * Handles structured security event formatting, enrichment, and real-time dispatch to AegisScan API.
 */

class AegisScanClient {
  /**
   * @param {Object} options
   * @param {string} [options.endpoint] - AegisScan instance URL (e.g. http://localhost:3000 or https://aegisscan.vercel.app)
   * @param {string} [options.apiKey] - AegisScan API Key
   * @param {string} [options.appName] - Application identifier
   * @param {string} [options.environment] - 'development', 'staging', or 'production'
   */
  constructor(options = {}) {
    this.endpoint = (options.endpoint || process.env.AEGISSCAN_ENDPOINT || 'http://localhost:3000').replace(/\/+$/, '');
    this.apiKey = options.apiKey || process.env.AEGISSCAN_API_KEY || 'aeg_live_default_key';
    this.appName = options.appName || process.env.AEGISSCAN_APP_NAME || 'AegiDemo-Portal';
    this.environment = options.environment || process.env.NODE_ENV || 'development';
    
    // In-memory telemetry log buffer for UI inspection & demo visualization
    this.eventBuffer = [];
    this.maxBufferSize = 50;
  }

  /**
   * Internal method to dispatch an event to AegisScan /api/security-events
   */
  async sendEvent(eventType, {
    userId = 'anonymous',
    sourceIp = '127.0.0.1',
    endpoint = '/',
    severity = 'INFO',
    status = 'flagged',
    action = 'ALERT',
    metadata = {}
  } = {}) {
    const eventId = 'evt_' + Math.random().toString(36).substring(2, 9) + Date.now().toString(36);
    const timestamp = new Date().toISOString();

    const payload = {
      id: eventId,
      event_type: eventType,
      type: eventType, // compatibility
      app_name: this.appName,
      environment: this.environment,
      user_id: userId,
      source_ip: sourceIp,
      endpoint: endpoint,
      severity: severity.toUpperCase(),
      status: status,
      action: action,
      timestamp: timestamp,
      metadata: {
        ...metadata,
        sdk: 'aegisscan-node-client',
        version: '1.2.0'
      }
    };

    const startTime = Date.now();
    let dispatchResult = {
      id: eventId,
      eventType,
      payload,
      timestamp,
      delivered: false,
      statusCode: null,
      latencyMs: 0,
      targetUrl: `${this.endpoint}/api/security-events`,
      error: null
    };

    try {
      const response = await fetch(`${this.endpoint}/api/security-events`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': this.apiKey,
          'Authorization': `Bearer ${this.apiKey}`
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(3500)
      });

      dispatchResult.latencyMs = Date.now() - startTime;
      dispatchResult.statusCode = response.status;
      dispatchResult.delivered = response.ok;

      if (response.ok) {
        dispatchResult.response = await response.json().catch(() => ({ status: 'ok' }));
        console.log(`\x1b[32m[AegisScan SDK] ✔ Dispatched ${eventType} (${severity}) to ${this.endpoint} [${dispatchResult.latencyMs}ms]\x1b[0m`);
      } else {
        const errBody = await response.text().catch(() => '');
        dispatchResult.error = `HTTP ${response.status}: ${errBody || response.statusText}`;
        console.warn(`\x1b[33m[AegisScan SDK] ⚠ Telemetry returned HTTP ${response.status} from ${this.endpoint}\x1b[0m`);
      }
    } catch (err) {
      dispatchResult.latencyMs = Date.now() - startTime;
      dispatchResult.delivered = false;
      dispatchResult.error = err.name === 'TimeoutError' ? 'Request timed out' : err.message;
      console.log(`\x1b[36m[AegisScan SDK] ℹ Telemetry logged locally (Live AegisScan remote offline: ${err.message})\x1b[0m`);
    }

    // Append to internal ring buffer for live frontend dashboard display
    this.eventBuffer.unshift(dispatchResult);
    if (this.eventBuffer.length > this.maxBufferSize) {
      this.eventBuffer.pop();
    }

    return dispatchResult;
  }

  /**
   * Trigger when user successfully logs in
   */
  async loginSuccess({ userId, sourceIp, endpoint = '/login', metadata = {} }) {
    return this.sendEvent('AUTH_LOGIN_SUCCESS', {
      userId,
      sourceIp,
      endpoint,
      severity: 'LOW',
      status: 'allowed',
      action: 'ALLOW',
      metadata: { reason: 'Valid credentials provided', ...metadata }
    });
  }

  /**
   * Trigger when login attempt fails
   */
  async loginFailed({ userId, sourceIp, endpoint = '/login', metadata = {} }) {
    return this.sendEvent('AUTH_LOGIN_FAILED', {
      userId,
      sourceIp,
      endpoint,
      severity: 'MEDIUM',
      status: 'flagged',
      action: 'CHALLENGE',
      metadata: { reason: 'Invalid username or password', ...metadata }
    });
  }

  /**
   * Trigger when unauthorized access is attempted on protected route
   */
  async unauthorizedAccess({ userId = 'anonymous', sourceIp, endpoint = '/admin', metadata = {} }) {
    return this.sendEvent('ACCESS_UNAUTHORIZED', {
      userId,
      sourceIp,
      endpoint,
      severity: 'HIGH',
      status: 'blocked',
      action: 'BLOCK',
      metadata: { reason: 'Missing or expired administrative session credentials', ...metadata }
    });
  }

  /**
   * Trigger when valid admin privileges are exercised
   */
  async adminAccess({ userId, sourceIp, endpoint = '/admin', metadata = {} }) {
    return this.sendEvent('ADMIN_PORTAL_ACCESSED', {
      userId,
      sourceIp,
      endpoint,
      severity: 'LOW',
      status: 'allowed',
      action: 'AUDIT',
      metadata: { reason: 'Privileged admin access session validated', ...metadata }
    });
  }

  /**
   * Trigger on suspicious input, SQLi, XSS or malicious payload
   */
  async suspiciousRequest({ userId = 'anonymous', sourceIp, endpoint = '/search', metadata = {} }) {
    return this.sendEvent('INJECTION_ATTEMPT_DETECTED', {
      userId,
      sourceIp,
      endpoint,
      severity: 'CRITICAL',
      status: 'blocked',
      action: 'BLOCK_AND_ISOLATE',
      metadata: { reason: 'High-confidence attack signature detected in request input', ...metadata }
    });
  }

  /**
   * Trigger on anomalous request burst / rate limit violation
   */
  async rateLimitBurst({ userId = 'anonymous', sourceIp, endpoint = '/api', metadata = {} }) {
    return this.sendEvent('RATE_LIMIT_EXCEEDED', {
      userId,
      sourceIp,
      endpoint,
      severity: 'HIGH',
      status: 'throttled',
      action: 'RATE_LIMIT_DELAY',
      metadata: { reason: 'Request frequency threshold exceeded (>10 reqs/sec)', ...metadata }
    });
  }

  /**
   * Retrieve recent events buffer
   */
  getRecentEvents() {
    return [...this.eventBuffer];
  }

  /**
   * Clear event buffer
   */
  clearEvents() {
    this.eventBuffer = [];
  }
}

module.exports = AegisScanClient;
