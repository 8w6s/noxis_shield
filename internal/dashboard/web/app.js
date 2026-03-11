// =============================================
// Noxis Shield Dashboard — app.js v2
// =============================================

const ADMIN_API = 'http://127.0.0.1:9091';
const startTime = Date.now();

// ---- UI ELEMENTS ----
const valRps = document.getElementById('valRps');
const valPeakRps = document.getElementById('valPeakRps');
const valBlocked = document.getElementById('valBlocked');
const valBlockRate = document.getElementById('valBlockRate');
const valPassed = document.getElementById('valPassed');
const valConns = document.getElementById('valConns');
const valEbpf = document.getElementById('valEbpf');
const valBanned = document.getElementById('valBanned');
const statusDot = document.getElementById('statusDot');
const statusText = document.getElementById('statusText');
const eventsBody = document.getElementById('eventsBody');
const offendersBody = document.getElementById('offendersBody');
const uptimeDisplay = document.getElementById('uptimeDisplay');

let allEvents = [];
let blockedIPsCache = [];
let peakRPS = 0;
let modeSince = null;
let wafBlockCount = 0;
let wafSessionHits = 0;

// ---- UPTIME TICKER ----
setInterval(() => {
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    const h = Math.floor(elapsed / 3600).toString().padStart(2, '0');
    const m = Math.floor((elapsed % 3600) / 60).toString().padStart(2, '0');
    const s = (elapsed % 60).toString().padStart(2, '0');
    if (uptimeDisplay) uptimeDisplay.textContent = `${h}:${m}:${s}`;
}, 1000);

// ---- TAB SWITCHING ----
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
});

function switchTab(id) {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.querySelector(`[data-tab="${id}"]`).classList.add('active');
    document.getElementById(`tab-${id}`).classList.add('active');
    if (id === 'blocklist') refreshBlocklist();
    if (id === 'waf') fetchWAFStatus();
}

// =============================================
// CHARTS
// =============================================
const ctx = document.getElementById('trafficChart').getContext('2d');
const ctx2 = document.getElementById('splitChart').getContext('2d');

let gradientBlue = ctx.createLinearGradient(0, 0, 0, 300);
gradientBlue.addColorStop(0, 'rgba(59, 130, 246, 0.4)');
gradientBlue.addColorStop(1, 'rgba(59, 130, 246, 0.0)');

let gradientRed = ctx.createLinearGradient(0, 0, 0, 300);
gradientRed.addColorStop(0, 'rgba(239, 68, 68, 0.4)');
gradientRed.addColorStop(1, 'rgba(239, 68, 68, 0.0)');

const commonOptions = {
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 0 }, // Disable animation for instant real-time visualization
    scales: {
        x: { display: false },
        y: {
            beginAtZero: true,
            grid: { color: 'rgba(255,255,255,0.05)', drawBorder: false },
            ticks: { color: '#94a3b8', font: { family: 'Outfit', size: 11 } }
        }
    },
    plugins: {
        legend: { display: false },
        tooltip: {
            backgroundColor: 'rgba(13,15,26,0.9)',
            titleFont: { family: 'Outfit', size: 13 },
            bodyFont: { family: 'Outfit', size: 12 },
            padding: 10, borderColor: 'rgba(255,255,255,0.1)', borderWidth: 1
        }
    },
    elements: {
        point: { radius: 0, hitRadius: 10, hoverRadius: 6 },
        line: { tension: 0.4, borderWidth: 3 }
    }
};

const trafficChart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: Array(60).fill(''),
        datasets: [{
            label: 'RPS', data: Array(60).fill(0),
            borderColor: '#3b82f6', backgroundColor: gradientBlue, fill: true,
        }]
    },
    options: commonOptions
});

let gradGreen = ctx2.createLinearGradient(0, 0, 0, 200);
gradGreen.addColorStop(0, 'rgba(34, 197, 94, 0.3)');
gradGreen.addColorStop(1, 'rgba(34, 197, 94, 0.0)');
let gradRed2 = ctx2.createLinearGradient(0, 0, 0, 200);
gradRed2.addColorStop(0, 'rgba(239, 68, 68, 0.3)');
gradRed2.addColorStop(1, 'rgba(239, 68, 68, 0.0)');

const splitChart = new Chart(ctx2, {
    type: 'line',
    data: {
        labels: Array(60).fill(''),
        datasets: [
            { label: 'Passed', data: Array(60).fill(0), borderColor: '#22c55e', backgroundColor: gradGreen, fill: true },
            { label: 'Blocked', data: Array(60).fill(0), borderColor: '#ef4444', backgroundColor: gradRed2, fill: true },
        ]
    },
    options: {
        ...commonOptions,
        plugins: {
            ...commonOptions.plugins,
            legend: {
                display: true,
                position: 'top',
                labels: { color: '#94a3b8', font: { family: 'Outfit', size: 11 }, boxWidth: 12 }
            }
        }
    }
});

let lastPassed = 0;
let lastBlocked = 0;
let lastEbpf = 0;

// =============================================
// WEBSOCKET
// =============================================
function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

    ws.onopen = () => {
        statusDot.className = 'pulse-dot active';
        statusText.textContent = 'Shield Active & Monitoring';
        statusText.style.color = 'var(--text-primary)';
        eventsBody.innerHTML = '';
    };

    ws.onclose = () => {
        statusDot.className = 'pulse-dot';
        statusText.textContent = 'Disconnected. Retrying...';
        statusText.style.color = 'var(--text-muted)';
        setTimeout(connectWebSocket, 2000);
    };

    ws.onerror = err => console.error('WebSocket Error:', err);

    ws.onmessage = event => {
        try { updateDashboard(JSON.parse(event.data)); }
        catch (e) { console.error('Failed to parse WS message', e); }
    };
}

function updateDashboard(stats) {
    const rps = Math.round(stats.currentRPS || 0);
    const passed = stats.passed || 0;
    const blocked = stats.blocked || 0;
    const ebpfDrops = stats.ebpfDrops || 0;
    
    // Calculate deltas over the last frame
    const passedDelta = Math.max(0, passed - lastPassed);
    const blockedDelta = Math.max(0, blocked - lastBlocked);
    const ebpfDelta = Math.max(0, ebpfDrops - lastEbpf);
    
    // Total instantaneous RPS hitting the box (including those dropped instantly in kernel)
    const instantRps = rps + ebpfDelta;

    if (instantRps > peakRPS) peakRPS = instantRps;

    valRps.innerHTML = `${instantRps} <span class="unit">req/s</span>`;
    if (valPeakRps) valPeakRps.textContent = `Peak: ${peakRPS} req/s`;

    const total = blocked + passed;
    const blockRate = total > 0 ? ((blocked / total) * 100).toFixed(1) : '0.0';

    valBlocked.textContent = formatNumber(blocked);
    if (valBlockRate) valBlockRate.textContent = `Block Rate: ${blockRate}%`;
    if (valPassed) valPassed.textContent = formatNumber(passed);
    if (valConns) valConns.textContent = `Active Connections: ${formatNumber(stats.activeConnections || 0)}`;
    if (valEbpf) valEbpf.textContent = formatNumber(stats.ebpfDrops || 0);
    if (valBanned) valBanned.textContent = `Banned IPs: ${stats.bannedIPs || 0}`;

    // --- Status glow ---
    const mode = stats.health?.defenseMode || stats.status || 'normal';
    updateDefenseMode(mode);

    // --- Charts ---
    trafficChart.data.datasets[0].data.shift();
    trafficChart.data.datasets[0].data.push(instantRps);
    trafficChart.data.labels.shift();
    trafficChart.data.labels.push('');
    trafficChart.update('none'); // Update without animation

    lastPassed = passed; 
    lastBlocked = blocked;
    lastEbpf = ebpfDrops;
    
    splitChart.data.datasets[0].data.shift(); splitChart.data.datasets[0].data.push(passedDelta);
    splitChart.data.datasets[1].data.shift(); splitChart.data.datasets[1].data.push(blockedDelta);
    splitChart.data.labels.shift(); splitChart.data.labels.push('');
    splitChart.update('none'); // Update without animation

    // --- Events log ---
    if (stats.recentEvents && stats.recentEvents.length > 0) {
        allEvents = stats.recentEvents;
        renderEvents();
    }

    // --- Top Offenders V2 ---
    if (stats.topOffenders) {
        renderOffenders(stats.topOffenders);
    }

    // --- Subsystem Health ---
    if (stats.health) {
        renderHealth(stats.health);
    }

    // --- WAF stats ---
    wafSessionHits = blocked;
    const wafTotalEl = document.getElementById('wafTotalBlocks');
    const wafSessionEl = document.getElementById('wafSessionHits');
    if (wafTotalEl) wafTotalEl.textContent = formatNumber(blocked);
    if (wafSessionEl) wafSessionEl.textContent = formatNumber(passedDelta + blockedDelta);
}

// =============================================
// DEFENSE MODE
// =============================================
let currentDefenseMode = '';

function updateDefenseMode(mode) {
    if (mode === currentDefenseMode) return;
    currentDefenseMode = mode;

    if (!modeSince) modeSince = new Date();

    // Navbar badge
    const navBadge = document.getElementById('defenseModeBadge');
    const modeLabel = document.getElementById('defenseModeLabel');
    const modeText = document.getElementById('defenseModeText');
    const modeSinceEl = document.getElementById('defenseModeSince');

    const modeConfig = {
        'normal':       { label: 'NORMAL',       cls: 'mode-normal' },
        'elevated':     { label: 'ELEVATED',     cls: 'mode-elevated' },
        'under_attack': { label: 'UNDER ATTACK', cls: 'mode-attack' },
        'recovery':     { label: 'RECOVERY',     cls: 'mode-recovery' },
    };
    const cfg = modeConfig[mode] || modeConfig['normal'];

    if (navBadge) { navBadge.textContent = cfg.label; navBadge.className = `mode-badge ${cfg.cls}`; }
    if (modeLabel) { modeLabel.textContent = cfg.label; modeLabel.className = `mode-badge ${cfg.cls}`; }
    if (modeText) modeText.textContent = mode;
    if (modeSinceEl) modeSinceEl.textContent = modeSince.toLocaleTimeString();

    // Header colors
    if (mode === 'under_attack') {
        statusDot.className = 'pulse-dot danger';
        statusText.textContent = 'UNDER ATTACK — Shield Blocking';
        statusText.style.color = 'var(--accent-red)';
        trafficChart.data.datasets[0].borderColor = '#ef4444';
        trafficChart.data.datasets[0].backgroundColor = gradientRed;
    } else {
        statusDot.className = 'pulse-dot active';
        statusText.textContent = mode === 'elevated' ? 'Elevated Threat Level' 
            : mode === 'recovery' ? 'Recovery Mode' : 'Traffic Normal';
        statusText.style.color = 'var(--text-primary)';
        trafficChart.data.datasets[0].borderColor = '#3b82f6';
        trafficChart.data.datasets[0].backgroundColor = gradientBlue;
    }
}

// =============================================
// SUBSYSTEM HEALTH
// =============================================
function renderHealth(health) {
    // Mitigation status row
    setMitigation('mitigationShield', health.shieldState === 'attached' ? 'Attached' : 'Fallback',
        health.shieldState === 'attached' ? 'ok' : 'warn');
    setMitigation('mitigationRedis', health.redisReachable ? 'Online' : 'Offline',
        health.redisReachable ? 'ok' : 'err');
    setMitigation('mitigationWAF', health.wafEnabled ? 'Enabled' : 'Disabled',
        health.wafEnabled ? 'ok' : 'warn');
    const upStatus = `${health.upstreamsActive}/${health.upstreamsTotal}`;
    setMitigation('mitigationUpstreams', `${upStatus} alive`,
        health.upstreamsActive === health.upstreamsTotal ? 'ok' : 'warn');

    // Health badges
    setBadge('healthShield', health.shieldState || '—',
        health.shieldState === 'attached' ? 'ok' : 'warn', health.shieldState);
    setBadge('healthRedis', health.redisReachable ? 'online' : 'offline',
        health.redisReachable ? 'ok' : 'err', health.redisReachable ? 'ok' : 'err');
    setBadge('healthWAF', health.wafEnabled ? 'enabled' : 'disabled',
        health.wafEnabled ? 'ok' : 'warn', health.wafEnabled ? 'ok' : 'err');
    setBadge('healthUpstreams', `${health.upstreamsActive}/${health.upstreamsTotal}`,
        health.upstreamsActive > 0 ? 'ok' : 'err', `${health.upstreamsActive}/${health.upstreamsTotal}`);

    const reconcilerAge = health.reconcilerLastRun
        ? `${Math.round((Date.now()/1000 - health.reconcilerLastRun))}s ago` : 'never';
    setBadge('healthReconciler', reconcilerAge,
        health.reconcilerLastRun ? 'ok' : 'warn', reconcilerAge);
    setBadge('healthDefense', health.defenseMode || 'unknown',
        health.defenseMode === 'normal' ? 'ok' :
        health.defenseMode === 'under_attack' ? 'err' : 'warn', health.defenseMode);
    
    const clusterBadge = document.getElementById('healthCluster');
    if (health.clusterEnabled && clusterBadge) {
        clusterBadge.style.display = 'flex';
        // +1 node to include self
        const val = `${health.clusterNodeCount + 1} node(s)`;
        setBadge('healthCluster', val, 'ok', val);
    } else if (clusterBadge) {
        clusterBadge.style.display = 'none';
    }
}

function setMitigation(id, text, statusClass) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = text;
    el.className = `mit-status ${statusClass}`;
}

function setBadge(id, valText, statusClass, displayVal) {
    const badge = document.getElementById(id);
    const valEl = document.getElementById(`${id}Val`);
    if (!badge || !valEl) return;
    badge.className = `health-badge ${statusClass}`;
    valEl.textContent = displayVal || valText;
}

// =============================================
// TOP OFFENDERS V2
// =============================================
function renderOffenders(offenders) {
    if (!offendersBody) return;

    if (!offenders || offenders.length === 0) {
        offendersBody.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No active threats detected</td></tr>`;
        return;
    }

    offendersBody.innerHTML = offenders.map(o => {
        let scoreClass = 'highlight-blue';
        if (o.score > 80) scoreClass = 'highlight-red';
        else if (o.score > 50) scoreClass = 'highlight-orange';
        else if (o.score > 25) scoreClass = 'highlight-yellow';

        const lastSeenAgo = o.lastSeen
            ? `${Math.round((Date.now()/1000 - o.lastSeen))}s ago` : '—';

        const sourceTag = o.lastSource
            ? `<span class="source-tag ${o.lastSource}">${o.lastSource}</span>` : '—';

        return `<tr>
            <td><code class="ip-code">${o.ip}</code></td>
            <td class="${scoreClass}" style="font-weight: 700;">${o.score}</td>
            <td>${sourceTag}</td>
            <td style="color:var(--text-muted);font-size:0.82em">${lastSeenAgo}</td>
        </tr>`;
    }).join('');
}

// =============================================
// EVENT LOG
// =============================================
function renderEvents() {
    const filterVal = (document.getElementById('logFilter')?.value || '').toLowerCase();
    const filtered = allEvents.filter(ev =>
        !filterVal || ev.type.toLowerCase().includes(filterVal) || ev.detail.toLowerCase().includes(filterVal)
    );

    const severityMap = {
        'attack_detected': { sev: '🔴 HIGH', mod: 'anomaly', color: 'var(--accent-red)' },
        'attack_resolved': { sev: '🟢 INFO', mod: 'anomaly', color: 'var(--accent-green)' },
        'mode_changed':    { sev: '🟡 WARN', mod: 'defense', color: 'var(--accent-yellow)' },
        'waf_block':       { sev: '🟠 MED',  mod: 'waf',     color: 'var(--accent-orange)' },
        'policy_block':    { sev: '🔵 INFO', mod: 'policy',  color: 'var(--accent-blue)' },
    };

    eventsBody.innerHTML = filtered.slice(0, 30).map(ev => {
        const meta = severityMap[ev.type] || { sev: '⚪ INFO', mod: ev.type.split('_')[0], color: 'var(--text-muted)' };
        return `<tr>
            <td style="color:var(--text-muted);font-size:0.85em;white-space:nowrap">${ev.time}</td>
            <td style="color:${meta.color};font-size:0.78em;font-weight:700;white-space:nowrap">${meta.sev}</td>
            <td><span class="source-tag ${meta.mod}">${meta.mod}</span></td>
            <td style="font-size:0.85em">${ev.detail}</td>
        </tr>`;
    }).join('') || `<tr><td colspan="4" class="text-center text-muted">No matching events.</td></tr>`;
}

document.getElementById('logFilter')?.addEventListener('input', renderEvents);

function exportLogs() {
    const data = JSON.stringify(allEvents, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `noxis_log_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`;
    a.click();
    URL.revokeObjectURL(url);
}

// =============================================
// ADMIN API CALLS
// =============================================
async function apiCall(method, path, resultId, body) {
    const el = document.getElementById(resultId);
    el.className = 'action-result loading';
    el.textContent = 'Processing...';
    try {
        const opts = { method };
        if (body) { opts.headers = { 'Content-Type': 'application/json' }; opts.body = JSON.stringify(body); }
        const resp = await fetch(`${ADMIN_API}${path}`, opts);
        const text = await resp.text();
        let msg;
        try { const j = JSON.parse(text); msg = JSON.stringify(j, null, 2); } catch { msg = text; }
        el.className = resp.ok ? 'action-result success' : 'action-result error';
        el.textContent = resp.ok ? '✅ ' + msg : '❌ ' + msg;
    } catch (err) {
        el.className = 'action-result error';
        el.textContent = '❌ Error: ' + err.message;
    }
}

function blockIP() {
    const ip = document.getElementById('blockIpInput').value.trim();
    const reason = document.getElementById('blockReasonInput').value.trim() || 'manual_dashboard';
    if (!ip) return showResult('blockResult', '❌ Please enter an IP address', 'error');
    apiCall('POST', `/api/block?ip=${encodeURIComponent(ip)}&reason=${encodeURIComponent(reason)}`, 'blockResult');
}

function unblockIP() {
    const ip = document.getElementById('unblockIpInput').value.trim();
    if (!ip) return showResult('unblockResult', '❌ Please enter an IP address', 'error');
    apiCall('POST', `/api/unblock?ip=${encodeURIComponent(ip)}`, 'unblockResult');
}

function whitelistIP() {
    const ip = document.getElementById('whitelistIpInput').value.trim();
    if (!ip) return showResult('whitelistResult', '❌ Please enter an IP address', 'error');
    apiCall('POST', `/api/whitelist?ip=${encodeURIComponent(ip)}`, 'whitelistResult');
}

async function clearAll() {
    if (!confirm('⚠️ Are you sure you want to clear ALL blocked IPs? This cannot be undone.')) return;
    await apiCall('POST', '/api/clear-all', 'clearResult');
    refreshBlocklist();
}

function setDefenseMode(mode) {
    modeSince = new Date();
    apiCall('POST', `/api/mode?mode=${encodeURIComponent(mode)}`, 'modeResult');
}

function resyncShield() {
    apiCall('POST', '/api/resync', 'resyncResult');
}

function showResult(id, msg, type) {
    const el = document.getElementById(id);
    if (!el) return;
    el.className = `action-result ${type}`;
    el.textContent = msg;
}

// ---- Blocklist Table V2 ----
async function refreshBlocklist() {
    const body = document.getElementById('blocklistBody');
    if (!body) return;
    body.innerHTML = '<tr><td colspan="6" class="text-center text-muted">Loading...</td></tr>';
    try {
        const resp = await fetch(`${ADMIN_API}/api/list`);
        const ips = await resp.json();
        blockedIPsCache = ips || [];
        renderBlocklistTable(blockedIPsCache);
    } catch (err) {
        body.innerHTML = `<tr><td colspan="6" class="text-center text-muted">Error: ${err.message}</td></tr>`;
    }
}

function renderBlocklistTable(ips) {
    const body = document.getElementById('blocklistBody');
    if (!body) return;
    if (!ips || ips.length === 0) {
        body.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No blocked IPs. System clean! ✅</td></tr>';
        return;
    }
    body.innerHTML = ips.map(entry => {
        const source = entry.source || entry.reason?.split('_')[0] || 'manual';
        const enforcement = (entry.source ? 'Redis + Shield' : 'Redis');
        return `<tr>
            <td><code class="ip-code">${entry.ip || '—'}</code></td>
            <td><span class="source-tag ${source}">${source}</span> <span style="color:var(--text-muted);font-size:0.8em">${entry.reason || ''}</span></td>
            <td style="color:var(--text-muted);font-size:0.8em">${enforcement}</td>
            <td style="color:var(--text-muted);font-size:0.85em">${entry.blockedAt ? new Date(entry.blockedAt).toLocaleString() : '—'}</td>
            <td style="color:var(--text-muted);font-size:0.85em">${entry.expiresAt ? new Date(entry.expiresAt).toLocaleString() : '—'}</td>
            <td>
                <button class="action-btn-sm warning" onclick="unblockFromTable('${entry.ip}')">Unblock</button>
                <button class="action-btn-sm success" onclick="whitelistFromTable('${entry.ip}')">Whitelist</button>
            </td>
        </tr>`;
    }).join('');
}

function filterBlocklist() {
    const val = document.getElementById('blocklistFilter')?.value.toLowerCase() || '';
    const filtered = blockedIPsCache.filter(e =>
        e.ip?.toLowerCase().includes(val) || e.reason?.toLowerCase().includes(val)
    );
    renderBlocklistTable(filtered);
}

async function unblockFromTable(ip) {
    try { await fetch(`${ADMIN_API}/api/unblock?ip=${encodeURIComponent(ip)}`, { method: 'POST' }); refreshBlocklist(); } catch { }
}

async function whitelistFromTable(ip) {
    try { await fetch(`${ADMIN_API}/api/whitelist?ip=${encodeURIComponent(ip)}`, { method: 'POST' }); refreshBlocklist(); } catch { }
}

// ---- WAF Controls ----
async function fetchWAFStatus() {
    try {
        const resp = await fetch(`${ADMIN_API}/api/waf/status`);
        const data = await resp.json();
        const toggle = document.getElementById('wafToggle');
        const label = document.getElementById('wafStatusLabel');
        const icon = document.getElementById('wafStatusIcon');
        if (toggle) toggle.checked = data.enabled;
        if (label) label.textContent = data.enabled ? 'WAF Enabled ✅' : 'WAF Disabled ⚠️';
        if (icon) icon.textContent = data.enabled ? '🛡️' : '⚠️';
    } catch { }
}

async function toggleWAF() {
    const el = document.getElementById('wafToggleResult');
    try {
        const resp = await fetch(`${ADMIN_API}/api/waf/toggle`, { method: 'POST' });
        const data = await resp.json();
        const label = document.getElementById('wafStatusLabel');
        const icon = document.getElementById('wafStatusIcon');
        if (label) label.textContent = data.enabled ? 'WAF Enabled ✅' : 'WAF Disabled ⚠️';
        if (icon) icon.textContent = data.enabled ? '🛡️' : '⚠️';
        el.className = 'action-result ' + (data.enabled ? 'success' : 'error');
        el.textContent = data.message;
    } catch (err) {
        el.className = 'action-result error';
        el.textContent = '❌ Failed to toggle WAF: ' + err.message;
    }
}

// =============================================
// HELPERS
// =============================================
function formatNumber(num) {
    return new Intl.NumberFormat('en-US').format(num || 0);
}

// Auto-refresh blocklist every 30s
setInterval(() => {
    const activeTab = document.querySelector('.tab-content.active');
    if (activeTab && activeTab.id === 'tab-blocklist') refreshBlocklist();
}, 30000);

// Launch!
connectWebSocket();
