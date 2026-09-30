/**
 * AegisScan Telemetry Demo - Client Controller
 */

// State
let activeTab = 'overview';
let telemetryEvents = [];
let currentUser = null;

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  checkSession();
  fetchTelemetry();
  setupEventListeners();

  // Poll for telemetry events every 3 seconds to keep feed fresh
  setInterval(fetchTelemetry, 3000);
});

// Tab Switcher
function initTabs() {
  const hash = window.location.hash.replace('#', '') || (window.location.pathname === '/login' ? 'login' : (window.location.pathname === '/admin' ? 'admin' : 'overview'));
  switchTab(hash);

  window.addEventListener('hashchange', () => {
    const newHash = window.location.hash.replace('#', '') || 'overview';
    switchTab(newHash);
  });
}

function switchTab(tabId) {
  const validTabs = ['overview', 'login', 'admin', 'search', 'simulator'];
  if (!validTabs.includes(tabId)) tabId = 'overview';
  
  activeTab = tabId;

  // Update nav links
  document.querySelectorAll('.tab-btn').forEach(btn => {
    const isTarget = btn.getAttribute('data-tab') === tabId;
    if (isTarget) {
      btn.className = 'tab-btn flex items-center gap-2 px-4 py-2.5 rounded-xl font-medium text-sm transition-all duration-200 bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-lg shadow-cyan-500/10';
    } else {
      btn.className = 'tab-btn flex items-center gap-2 px-4 py-2.5 rounded-xl font-medium text-sm transition-all duration-200 text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent';
    }
  });

  // Update tab panels
  document.querySelectorAll('.tab-panel').forEach(panel => {
    if (panel.id === `tab-${tabId}`) {
      panel.classList.remove('hidden');
    } else {
      panel.classList.add('hidden');
    }
  });

  // Auto-trigger admin check if admin tab opened
  if (tabId === 'admin') {
    loadAdminPortalData();
  }
}

// Session & Auth state check
async function checkSession() {
  try {
    const res = await fetch('/api/session');
    const data = await res.json();
    currentUser = data.user;
    updateUserUI(currentUser);
  } catch (err) {
    console.error('Session check failed:', err);
  }
}

function updateUserUI(user) {
  const userStatusBadge = document.getElementById('user-status-badge');
  const loginNavBtn = document.getElementById('login-nav-text');
  const logoutBtn = document.getElementById('logout-btn');

  if (user) {
    userStatusBadge.innerHTML = `
      <span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
        <span class="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
        <i class="fa-solid fa-shield-halved"></i> ${user.email} (${user.role})
      </span>
    `;
    if (loginNavBtn) loginNavBtn.innerText = 'Profile';
    if (logoutBtn) logoutBtn.classList.remove('hidden');
  } else {
    userStatusBadge.innerHTML = `
      <span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium bg-slate-800 text-slate-400 border border-slate-700">
        <i class="fa-solid fa-user-slash"></i> Anonymous User
      </span>
    `;
    if (loginNavBtn) loginNavBtn.innerText = 'Login';
    if (logoutBtn) logoutBtn.classList.add('hidden');
  }
}

// Setup Form and Button Listeners
function setupEventListeners() {
  // Login Form
  const loginForm = document.getElementById('login-form');
  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('login-email').value.trim();
      const password = document.getElementById('login-password').value;
      const submitBtn = document.getElementById('login-submit-btn');

      submitBtn.disabled = true;
      submitBtn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Authenticating...`;

      try {
        const res = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password })
        });

        const data = await res.json();

        if (res.ok && data.success) {
          showToast('success', 'Authentication Successful', data.message);
          currentUser = data.user;
          updateUserUI(currentUser);
          fetchTelemetry();
          setTimeout(() => switchTab('admin'), 800);
        } else {
          showToast('error', 'Login Failed - Telemetry Dispatched', data.message);
          fetchTelemetry();
        }
      } catch (err) {
        showToast('error', 'Connection Error', err.message);
      } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = `<i class="fa-solid fa-arrow-right-to-bracket"></i> Sign In to Account`;
      }
    });
  }

  // Logout Button
  const logoutBtn = document.getElementById('logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      await fetch('/api/logout', { method: 'POST' });
      currentUser = null;
      updateUserUI(null);
      showToast('info', 'Logged Out', 'Administrative session ended.');
      switchTab('login');
      loadAdminPortalData();
    });
  }

  // Search Form
  const searchForm = document.getElementById('search-form');
  if (searchForm) {
    searchForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const query = document.getElementById('search-input').value;
      executeSearch(query);
    });
  }
}

// Quick credential autofill
window.fillCredentials = function(email, pass) {
  document.getElementById('login-email').value = email;
  document.getElementById('login-password').value = pass;
};

// Search Execution
async function executeSearch(query) {
  const resultsContainer = document.getElementById('search-results');
  resultsContainer.innerHTML = `
    <div class="py-12 text-center text-slate-400">
      <i class="fa-solid fa-circle-notch fa-spin text-2xl text-cyan-400 mb-3"></i>
      <p>Analyzing query parameters against AegisScan IDS rules...</p>
    </div>
  `;

  try {
    const res = await fetch('/api/search', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query })
    });

    const data = await res.json();
    fetchTelemetry();

    if (!res.ok || data.threatDetected) {
      showToast('critical', `Threat Intercepted: ${data.threatType}`, data.message);
      resultsContainer.innerHTML = `
        <div class="p-6 rounded-2xl bg-rose-950/40 border border-rose-500/40 text-rose-200">
          <div class="flex items-start gap-4">
            <div class="p-3 rounded-xl bg-rose-500/20 text-rose-400 text-2xl">
              <i class="fa-solid fa-shield-virus"></i>
            </div>
            <div>
              <h3 class="text-lg font-bold text-white mb-1">🚨 Security Intercept: ${data.threatType}</h3>
              <p class="text-sm text-rose-300/90 mb-3">${data.message}</p>
              <div class="p-3 bg-black/40 rounded-xl font-mono text-xs text-rose-300 border border-rose-500/20">
                <strong>Quarantined Query:</strong> <code>${escapeHtml(query)}</code>
              </div>
              <p class="text-xs text-rose-400 mt-2">
                ✔ High-priority telemetry dispatch logged to AegisScan SIEM endpoint.
              </p>
            </div>
          </div>
        </div>
      `;
    } else {
      if (data.results.length === 0) {
        resultsContainer.innerHTML = `
          <div class="py-12 text-center text-slate-400">
            <i class="fa-solid fa-magnifying-glass text-3xl mb-3 text-slate-600"></i>
            <p>No catalog items matching "<strong>${escapeHtml(query)}</strong>"</p>
          </div>
        `;
      } else {
        resultsContainer.innerHTML = `
          <div class="mb-3 text-xs text-slate-400 flex items-center justify-between">
            <span>Found ${data.count} security products (Sanitized Query)</span>
            <span class="text-emerald-400"><i class="fa-solid fa-check-circle"></i> Clean Query</span>
          </div>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            ${data.results.map(prod => `
              <div class="p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition">
                <div class="flex items-start justify-between mb-2">
                  <h4 class="font-semibold text-white text-sm">${escapeHtml(prod.name)}</h4>
                  <span class="text-xs font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">${prod.price}</span>
                </div>
                <p class="text-xs text-slate-400 mb-2">${escapeHtml(prod.desc)}</p>
                <span class="inline-block text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-slate-800 text-slate-400">${escapeHtml(prod.category)}</span>
              </div>
            `).join('')}
          </div>
        `;
      }
    }
  } catch (err) {
    showToast('error', 'Search Error', err.message);
  }
}

// Fill sample queries in search tab
window.setSearchQuery = function(text) {
  document.getElementById('search-input').value = text;
  executeSearch(text);
};

// Load Admin Portal Data
async function loadAdminPortalData() {
  const adminContent = document.getElementById('admin-content-area');
  adminContent.innerHTML = `
    <div class="py-12 text-center text-slate-400">
      <i class="fa-solid fa-circle-notch fa-spin text-2xl text-cyan-400 mb-3"></i>
      <p>Verifying administrative authorization token...</p>
    </div>
  `;

  try {
    const res = await fetch('/api/admin/data');
    const data = await res.json();
    fetchTelemetry();

    if (!res.ok || !data.success) {
      showToast('warning', 'Unauthorized Access Blocked', data.message || 'Access Denied');
      adminContent.innerHTML = `
        <div class="p-8 rounded-2xl bg-gradient-to-b from-rose-950/40 to-slate-900/80 border border-rose-500/30 text-center">
          <div class="w-16 h-16 rounded-2xl bg-rose-500/10 border border-rose-500/30 text-rose-400 flex items-center justify-center text-3xl mx-auto mb-4">
            <i class="fa-solid fa-lock"></i>
          </div>
          <h3 class="text-xl font-bold text-white mb-2">403 Forbidden - Admin Access Denied</h3>
          <p class="text-sm text-slate-400 max-w-md mx-auto mb-6">
            You do not possess valid administrative session credentials. This unauthorized access probe has been intercepted and logged to AegisScan.
          </p>
          <div class="flex items-center justify-center gap-3">
            <button onclick="switchTab('login')" class="px-5 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-sm transition">
              <i class="fa-solid fa-key mr-1.5"></i> Authenticate as Admin
            </button>
            <button onclick="triggerSimulation('unauthorized')" class="px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium text-sm transition border border-slate-700">
              <i class="fa-solid fa-flask mr-1.5"></i> Simulate External Probe
            </button>
          </div>
        </div>
      `;
    } else {
      adminContent.innerHTML = `
        <div class="space-y-6">
          <div class="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-between">
            <div class="flex items-center gap-3">
              <span class="w-3 h-3 rounded-full bg-emerald-400 animate-ping"></span>
              <span class="text-sm font-semibold text-emerald-300">Verified Admin Session Active (Role: ${currentUser?.role || 'SUPER_ADMIN'})</span>
            </div>
            <span class="text-xs font-mono text-emerald-400/80">Audit ID: ${data.telemetry?.id || 'SEC-AUDIT-VALID'}</span>
          </div>

          <!-- Server Metrics Grid -->
          <div class="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div class="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
              <p class="text-xs text-slate-400 uppercase font-medium">Uptime</p>
              <p class="text-xl font-bold text-white mt-1">${data.data.serverMetrics.uptime}</p>
            </div>
            <div class="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
              <p class="text-xs text-slate-400 uppercase font-medium">Active Nodes</p>
              <p class="text-xl font-bold text-cyan-400 mt-1">${data.data.serverMetrics.activeNodes} Cluster Nodes</p>
            </div>
            <div class="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
              <p class="text-xs text-slate-400 uppercase font-medium">Load Average</p>
              <p class="text-xl font-bold text-amber-400 mt-1">${data.data.serverMetrics.loadAverage}</p>
            </div>
            <div class="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
              <p class="text-xs text-slate-400 uppercase font-medium">Threat Level</p>
              <p class="text-sm font-bold text-emerald-400 mt-2">PROTECTED</p>
            </div>
          </div>

          <!-- Vault Keys Table -->
          <div class="rounded-xl border border-slate-800 overflow-hidden bg-slate-900/50">
            <div class="px-4 py-3 bg-slate-800/60 border-b border-slate-800 flex items-center justify-between">
              <h4 class="text-sm font-bold text-white flex items-center gap-2">
                <i class="fa-solid fa-key text-amber-400"></i> Protected Infrastructure Secrets
              </h4>
              <span class="text-xs px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">RESTRICTED_TIER_1</span>
            </div>
            <div class="divide-y divide-slate-800/80 text-xs">
              ${data.data.infrastructureKeys.map(k => `
                <div class="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div>
                    <p class="font-bold text-slate-200">${k.name}</p>
                    <p class="font-mono text-slate-400 mt-0.5">${k.fingerprint}</p>
                  </div>
                  <span class="text-slate-500">Rotated: ${k.rotated}</span>
                </div>
              `).join('')}
            </div>
          </div>
        </div>
      `;
    }
  } catch (err) {
    showToast('error', 'Admin API Error', err.message);
  }
}

// Attack Simulation Trigger
window.triggerSimulation = async function(attackType) {
  const btn = document.getElementById(`sim-btn-${attackType}`);
  if (btn) {
    btn.disabled = true;
    btn.classList.add('opacity-50', 'pointer-events-none');
  }

  showToast('info', 'Executing Simulation', `Triggering ${attackType.toUpperCase()} test payload...`);

  try {
    const res = await fetch(`/api/simulate/${attackType}`, { method: 'POST' });
    const data = await res.json();

    fetchTelemetry();

    if (attackType === 'brute-force') {
      showToast('warning', 'Brute Force Fired', `Dispatched ${data.dispatchedCount} failed login alerts in rapid burst.`);
    } else if (attackType === 'sqli') {
      showToast('critical', 'SQL Injection Simulated', 'High-severity database probe telemetry dispatched.');
    } else if (attackType === 'unauthorized') {
      showToast('warning', 'BOLA Probe Simulated', 'Unauthorized access alert dispatched to AegisScan.');
    } else if (attackType === 'rate-limit') {
      showToast('warning', 'Rate Limit Burst Simulated', `Flooded with ${data.dispatchedCount} rapid requests.`);
    } else if (attackType === 'xss') {
      showToast('critical', 'XSS Attack Simulated', 'Script injection signature quarantined and reported.');
    }
  } catch (err) {
    showToast('error', 'Simulation Failed', err.message);
  } finally {
    if (btn) {
      setTimeout(() => {
        btn.disabled = false;
        btn.classList.remove('opacity-50', 'pointer-events-none');
      }, 1000);
    }
  }
};

// Fetch Telemetry Events from Server
async function fetchTelemetry() {
  try {
    const res = await fetch('/api/telemetry/events');
    const data = await res.json();
    telemetryEvents = data.events || [];
    renderTelemetryFeed(telemetryEvents);
    updateTelemetryCounters(telemetryEvents);
  } catch (err) {
    console.error('Failed to fetch telemetry:', err);
  }
}

// Clear Telemetry Events
window.clearTelemetryEvents = async function() {
  await fetch('/api/telemetry/events', { method: 'DELETE' });
  fetchTelemetry();
  showToast('info', 'Telemetry Cleared', 'In-memory telemetry buffer reset.');
};

// Update Top Level Event Counters
function updateTelemetryCounters(events) {
  const totalCountEl = document.getElementById('count-total-events');
  const criticalCountEl = document.getElementById('count-critical-events');
  const deliveredCountEl = document.getElementById('count-delivered-events');

  if (totalCountEl) totalCountEl.innerText = events.length;
  if (criticalCountEl) {
    criticalCountEl.innerText = events.filter(e => e.payload?.severity === 'CRITICAL' || e.payload?.severity === 'HIGH').length;
  }
  if (deliveredCountEl) {
    deliveredCountEl.innerText = events.filter(e => e.delivered).length;
  }
}

// Render Telemetry Event Feed
function renderTelemetryFeed(events) {
  const container = document.getElementById('telemetry-feed');
  if (!container) return;

  if (events.length === 0) {
    container.innerHTML = `
      <div class="py-16 text-center text-slate-500">
        <i class="fa-solid fa-radar text-4xl mb-3 text-slate-700"></i>
        <p class="text-sm">No security telemetry events captured yet.</p>
        <p class="text-xs text-slate-600 mt-1">Try simulating an attack or submitting a search query.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = events.map(evt => {
    const p = evt.payload;
    const severityColors = {
      CRITICAL: 'bg-rose-500/20 text-rose-400 border-rose-500/30',
      HIGH: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
      MEDIUM: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
      LOW: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
      INFO: 'bg-slate-700 text-slate-300 border-slate-600'
    };

    const statusBadge = evt.delivered 
      ? `<span class="inline-flex items-center gap-1 text-[11px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20"><i class="fa-solid fa-cloud-arrow-up"></i> Dispatched (${evt.latencyMs}ms)</span>`
      : `<span class="inline-flex items-center gap-1 text-[11px] font-mono text-cyan-300 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20" title="${evt.error || 'Buffered'}"><i class="fa-solid fa-circle-dot"></i> Captured (${evt.latencyMs}ms)</span>`;

    const sevBadgeClass = severityColors[p?.severity] || severityColors.INFO;

    return `
      <div class="p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div class="flex items-start gap-3">
          <div class="p-2.5 rounded-lg ${p?.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400' : 'bg-slate-800 text-cyan-400'} text-lg">
            <i class="fa-solid ${getEventIcon(p?.event_type)}"></i>
          </div>
          <div>
            <div class="flex items-center gap-2 flex-wrap">
              <span class="font-bold text-white text-sm font-mono">${escapeHtml(p?.event_type || evt.eventType)}</span>
              <span class="text-[10px] font-bold px-2 py-0.5 rounded border ${sevBadgeClass}">${p?.severity}</span>
              ${statusBadge}
            </div>
            <div class="text-xs text-slate-400 mt-1 flex items-center gap-3 flex-wrap">
              <span><i class="fa-solid fa-user text-slate-500 mr-1"></i>${escapeHtml(p?.user_id || 'anonymous')}</span>
              <span><i class="fa-solid fa-network-wired text-slate-500 mr-1"></i>${escapeHtml(p?.source_ip || '127.0.0.1')}</span>
              <span><i class="fa-solid fa-link text-slate-500 mr-1"></i>${escapeHtml(p?.endpoint || '/')}</span>
              <span class="text-slate-500"><i class="fa-regular fa-clock mr-1"></i>${new Date(evt.timestamp).toLocaleTimeString()}</span>
            </div>
          </div>
        </div>

        <div class="flex items-center gap-2 self-end md:self-center">
          <button onclick="inspectPayload('${evt.id}')" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-300 border border-slate-700 hover:border-cyan-500/40 transition">
            <i class="fa-solid fa-code mr-1"></i> Payload
          </button>
        </div>
      </div>
    `;
  }).join('');
}

function getEventIcon(type = '') {
  if (type.includes('LOGIN_FAILED') || type.includes('BRUTE')) return 'fa-user-lock';
  if (type.includes('LOGIN_SUCCESS')) return 'fa-user-check';
  if (type.includes('INJECTION')) return 'fa-bug-slash';
  if (type.includes('UNAUTHORIZED') || type.includes('ACCESS')) return 'fa-shield-halved';
  if (type.includes('RATE_LIMIT')) return 'fa-gauge-high';
  return 'fa-bolt';
}

// Payload Inspector Modal
window.inspectPayload = function(eventId) {
  const evt = telemetryEvents.find(e => e.id === eventId);
  if (!evt) return;

  const modal = document.getElementById('payload-modal');
  const modalBody = document.getElementById('modal-payload-content');

  modalBody.textContent = JSON.stringify(evt, null, 2);
  modal.classList.remove('hidden');
};

window.closePayloadModal = function() {
  document.getElementById('payload-modal').classList.add('hidden');
};

window.copyPayloadJson = function() {
  const content = document.getElementById('modal-payload-content').textContent;
  navigator.clipboard.writeText(content);
  showToast('info', 'Copied', 'JSON payload copied to clipboard');
};

// Toast Notifications System
function showToast(type, title, message) {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  const typeConfig = {
    success: { border: 'border-emerald-500/40', bg: 'bg-slate-900/95', icon: 'fa-circle-check', iconColor: 'text-emerald-400' },
    error: { border: 'border-rose-500/40', bg: 'bg-slate-900/95', icon: 'fa-circle-xmark', iconColor: 'text-rose-400' },
    critical: { border: 'border-rose-500/60 shadow-rose-500/20 shadow-lg', bg: 'bg-rose-950/90', icon: 'fa-triangle-exclamation', iconColor: 'text-rose-400' },
    warning: { border: 'border-amber-500/40', bg: 'bg-slate-900/95', icon: 'fa-triangle-exclamation', iconColor: 'text-amber-400' },
    info: { border: 'border-cyan-500/40', bg: 'bg-slate-900/95', icon: 'fa-circle-info', iconColor: 'text-cyan-400' }
  };

  const cfg = typeConfig[type] || typeConfig.info;

  toast.className = `toast p-4 rounded-xl border ${cfg.border} ${cfg.bg} backdrop-blur-md shadow-2xl flex items-start gap-3`;
  toast.innerHTML = `
    <div class="text-xl ${cfg.iconColor} mt-0.5">
      <i class="fa-solid ${cfg.icon}"></i>
    </div>
    <div class="flex-1">
      <h4 class="text-sm font-bold text-white">${escapeHtml(title)}</h4>
      <p class="text-xs text-slate-300 mt-0.5 leading-relaxed">${escapeHtml(message)}</p>
    </div>
    <button onclick="this.parentElement.remove()" class="text-slate-400 hover:text-white text-sm">
      <i class="fa-solid fa-xmark"></i>
    </button>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add('toast-fadeout');
    setTimeout(() => toast.remove(), 300);
  }, 4500);
}

// Utility: Escape HTML
function escapeHtml(str) {
  if (typeof str !== 'string') return str;
  return str.replace(/[&<>"']/g, function(m) {
    return {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    }[m];
  });
}
