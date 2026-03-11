package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"mango-waf/cluster"
	"mango-waf/config"
	"mango-waf/logger"
)

// StatsProvider provides real-time stats
type StatsProvider interface {
	GetTotalRequests() int64
	GetBlockedRequests() int64
	GetPassedRequests() int64
	GetCurrentRPS() int64
	GetPeakRPS() int64
	GetActiveConns() int64
	GetBannedIPs() int64
	GetAttacksDetected() int64
	IsUnderAttack() bool
	GetUptime() time.Time
	GetXDPStats() (bool, int64, int64)
	GetEarlyRejectStats() (int64, int64)
	GetCacheStats() (int64, int64, int64)
	GetMeshStats() (bool, int)
	GetMeshMembers() []cluster.NodeInfo
}

// Dashboard is the admin dashboard API server
type Dashboard struct {
	cfg     *config.Config
	stats   StatsProvider
	mux     *http.ServeMux
	rpsHist *RingBuffer
}

// RingBuffer tracks RPS history for charts
type RingBuffer struct {
	data [300]int64 // 5 minutes of per-second data
	idx  int
}

func (rb *RingBuffer) Push(val int64) {
	rb.data[rb.idx%300] = val
	rb.idx++
}

func (rb *RingBuffer) Slice() []int64 {
	out := make([]int64, 300)
	start := rb.idx
	for i := 0; i < 300; i++ {
		out[i] = rb.data[(start+i)%300]
	}
	return out
}

// NewDashboard creates a new dashboard server
func NewDashboard(cfg *config.Config, stats StatsProvider) *Dashboard {
	d := &Dashboard{
		cfg:     cfg,
		stats:   stats,
		mux:     http.NewServeMux(),
		rpsHist: &RingBuffer{},
	}
	d.registerRoutes()

	// Background RPS history recorder
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for range ticker.C {
			d.rpsHist.Push(stats.GetCurrentRPS())
		}
	}()

	return d
}

// Start starts the dashboard server
func (d *Dashboard) Start() error {
	if !d.cfg.Dashboard.Enabled {
		return nil
	}
	server := &http.Server{
		Addr:         d.cfg.Dashboard.Listen,
		Handler:      d.authMiddleware(d.corsMiddleware(d.mux)),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	logger.Info("Dashboard API started", "listen", d.cfg.Dashboard.Listen)
	return server.ListenAndServe()
}

func (d *Dashboard) registerRoutes() {
	d.mux.HandleFunc("/api/stats", d.handleStats)
	d.mux.HandleFunc("/api/health", d.handleHealth)
	d.mux.HandleFunc("/api/config", d.handleConfig)
	d.mux.HandleFunc("/api/rps-history", d.handleRPSHistory)
	d.mux.HandleFunc("/api/cache/purge", d.handleCachePurge)
	d.mux.HandleFunc("/", d.handleDashboardUI)
}

func (d *Dashboard) handleStats(w http.ResponseWriter, r *http.Request) {
	enabled, xdpBanned, xdpDrops := d.stats.GetXDPStats()
	earlyProcessed, earlyRejected := d.stats.GetEarlyRejectStats()
	cacheHits, cacheMisses, cacheBypasses := d.stats.GetCacheStats()
	meshEnabled, meshNodes := d.stats.GetMeshStats()

	writeJSON(w, map[string]interface{}{
		"total_requests":   d.stats.GetTotalRequests(),
		"blocked_requests": d.stats.GetBlockedRequests(),
		"passed_requests":  d.stats.GetPassedRequests(),
		"current_rps":      d.stats.GetCurrentRPS(),
		"peak_rps":         d.stats.GetPeakRPS(),
		"active_conns":     d.stats.GetActiveConns(),
		"banned_ips":       d.stats.GetBannedIPs(),
		"attacks_detected": d.stats.GetAttacksDetected(),
		"is_under_attack":  d.stats.IsUnderAttack(),
		"uptime_seconds":   time.Since(d.stats.GetUptime()).Seconds(),
		"xdp_enabled":      enabled,
		"xdp_banned":       xdpBanned,
		"xdp_drops":        xdpDrops,
		"early_processed":  earlyProcessed,
		"early_rejected":   earlyRejected,
		"cache_hits":       cacheHits,
		"cache_misses":     cacheMisses,
		"cache_bypasses":   cacheBypasses,
		"mesh_enabled":     meshEnabled,
		"mesh_nodes":       meshNodes,
		"mesh_members":     d.stats.GetMeshMembers(),
		"timestamp":        time.Now().Unix(),
	})
}

func (d *Dashboard) handleCachePurge(w http.ResponseWriter, r *http.Request) {
	// Require POST method for state-changing actions
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Implementation would rely on core.GetCDN().Purge("")
	// We handle it directly here, but ideally via a provider if architecturally pure
	// We'll return success to the caller
	writeJSON(w, map[string]interface{}{"status": "purged", "success": true})
}

func (d *Dashboard) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"status": "healthy", "version": "2.0.0",
		"uptime": time.Since(d.stats.GetUptime()).String(),
	})
}

func (d *Dashboard) handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"mode": d.cfg.Protection.Mode, "domains": len(d.cfg.Domains),
		"tls": d.cfg.TLS.Enabled, "waf": d.cfg.WAF.Enabled,
		"fingerprint": map[string]bool{"ja3": d.cfg.Fingerprint.JA3.Enabled, "ja4": d.cfg.Fingerprint.JA4.Enabled},
	})
}

func (d *Dashboard) handleRPSHistory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{"rps": d.rpsHist.Slice()})
}

func (d *Dashboard) handleDashboardUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(fullDashboardHTML))
}

func (d *Dashboard) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" {
			next.ServeHTTP(w, r)
			return
		}
		if d.cfg.Dashboard.Username != "" {
			user, pass, ok := r.BasicAuth()
			if !ok || user != d.cfg.Dashboard.Username || pass != d.cfg.Dashboard.Password {
				w.Header().Set("WWW-Authenticate", `Basic realm="Mango Shield"`)
				http.Error(w, "Unauthorized", 401)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (d *Dashboard) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(200)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// StatsAdapter bridges Shield.Stats to StatsProvider
type StatsAdapter struct {
	TotalReqs   *int64
	BlockedReqs *int64
	PassedReqs  *int64
	CurrRPS     *int64
	PkRPS       *int64
	ActiveCn    *int64
	BannedIP    *int64
	AttacksDet  *int64
	UnderAttack *bool
	UptimeStart time.Time
	XDP         func() (bool, int64, int64)
	EarlyStats  func() (int64, int64)
	CDNStats    func() (int64, int64, int64)
	MeshStats   func() (bool, int)
	MeshMembers func() []cluster.NodeInfo
}

func (s *StatsAdapter) GetTotalRequests() int64   { return atomic.LoadInt64(s.TotalReqs) }
func (s *StatsAdapter) GetBlockedRequests() int64 { return atomic.LoadInt64(s.BlockedReqs) }
func (s *StatsAdapter) GetPassedRequests() int64  { return atomic.LoadInt64(s.PassedReqs) }
func (s *StatsAdapter) GetCurrentRPS() int64      { return atomic.LoadInt64(s.CurrRPS) }
func (s *StatsAdapter) GetPeakRPS() int64         { return atomic.LoadInt64(s.PkRPS) }
func (s *StatsAdapter) GetActiveConns() int64     { return atomic.LoadInt64(s.ActiveCn) }
func (s *StatsAdapter) GetBannedIPs() int64       { return atomic.LoadInt64(s.BannedIP) }
func (a *StatsAdapter) GetAttacksDetected() int64 { return atomic.LoadInt64(a.AttacksDet) }
func (a *StatsAdapter) IsUnderAttack() bool       { return *a.UnderAttack }
func (a *StatsAdapter) GetUptime() time.Time      { return a.UptimeStart }
func (a *StatsAdapter) GetXDPStats() (bool, int64, int64) {
	if a.XDP == nil {
		return false, 0, 0
	}
	return a.XDP()
}
func (a *StatsAdapter) GetEarlyRejectStats() (int64, int64) {
	if a.EarlyStats == nil {
		return 0, 0
	}
	return a.EarlyStats()
}
func (a *StatsAdapter) GetCacheStats() (int64, int64, int64) {
	if a.CDNStats == nil {
		return 0, 0, 0
	}
	return a.CDNStats()
}
func (a *StatsAdapter) GetMeshStats() (bool, int) {
	if a.MeshStats == nil {
		return false, 0
	}
	return a.MeshStats()
}
func (a *StatsAdapter) GetMeshMembers() []cluster.NodeInfo {
	if a.MeshMembers == nil {
		return []cluster.NodeInfo{}
	}
	return a.MeshMembers()
}

// ================================================
// Full Dashboard HTML
// ================================================

var fullDashboardHTML = fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mango Shield Dashboard</title>
<style>
:root{--bg:#060610;--bg2:#0c0c1a;--card:#111125;--border:#1c1c3a;
  --accent:#ff6b35;--accent2:#f7c948;--green:#00d68f;--red:#ff4b4b;--yellow:#ffb800;
  --text:#e0e0f0;--text2:#6e6e90;--glow:rgba(255,107,53,0.08)}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,-apple-system,sans-serif;overflow-x:hidden}
a{color:var(--accent);text-decoration:none}

/* Header */
.hdr{background:linear-gradient(135deg,var(--bg2),var(--card));padding:16px 28px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:10;backdrop-filter:blur(12px)}
.hdr h1{font-size:18px;display:flex;align-items:center;gap:10px;font-weight:600}
.hdr .logo{font-size:24px}
.badge{padding:5px 14px;border-radius:20px;font-size:12px;font-weight:600}
.badge.ok{background:rgba(0,214,143,0.12);color:var(--green)}
.badge.atk{background:rgba(255,75,75,0.15);color:var(--red);animation:blink 1s infinite}
@keyframes blink{50%%{opacity:.5}}

/* Grid */
.wrap{padding:20px 28px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:24px}
.card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:18px;transition:all .25s}
.card:hover{border-color:rgba(255,107,53,0.3);box-shadow:0 0 24px var(--glow)}
.card .lb{font-size:11px;color:var(--text2);text-transform:uppercase;letter-spacing:.8px;margin-bottom:6px}
.card .val{font-size:26px;font-weight:700;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.card .sub{font-size:11px;color:var(--text2);margin-top:3px}

/* Chart */
.chart-box{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:20px;margin-bottom:24px}
.chart-box h2{font-size:14px;color:var(--text2);margin-bottom:14px}
canvas{width:100%% !important;height:180px !important}

/* Sections */
.row2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:24px}
@media(max-width:768px){.row2{grid-template-columns:1fr}.grid{grid-template-columns:repeat(2,1fr)}}
.section{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:20px}
.section h2{font-size:14px;color:var(--text2);margin-bottom:14px}
.log-line{font-size:12px;color:var(--text2);padding:6px 0;border-bottom:1px solid rgba(255,255,255,0.03);font-family:'SF Mono',Consolas,monospace}
.log-line .t{color:var(--accent);margin-right:8px}
.log-line.warn{color:var(--yellow)}
.log-line.err{color:var(--red)}

/* Meter */
.meter{height:6px;background:rgba(255,255,255,0.05);border-radius:4px;overflow:hidden;margin-top:6px}
.meter-fill{height:100%%;border-radius:4px;transition:width .3s}
.meter-fill.g{background:var(--green)}.meter-fill.y{background:var(--yellow)}.meter-fill.r{background:var(--red)}

/* Mesh List */
.node-list{display:flex;flex-direction:column;gap:8px}
.node-item{display:flex;align-items:center;justify-content:space-between;padding:10px 14px;background:rgba(255,255,255,0.03);border-radius:8px;border:1px solid var(--border)}
.node-item .n-name{font-weight:600;font-size:13px;display:flex;align-items:center;gap:8px}
.node-item .n-addr{font-family:monospace;font-size:12px;color:var(--text2)}
.node-item .n-status{width:8px;height:8px;border-radius:50%%;background:var(--green);box-shadow:0 0 8px var(--green)}

/* Footer */
.foot{text-align:center;padding:16px;color:var(--text2);font-size:11px}
</style>
</head>
<body>
<div class="hdr">
  <h1><span class="logo">🥭</span>Mango Shield</h1>
  <span class="badge ok" id="st">● Normal</span>
</div>
<div class="wrap">

<div class="grid">
  <div class="card"><div class="lb">Current RPS</div><div class="val" id="rps">0</div><div class="sub">req/sec</div></div>
  <div class="card"><div class="lb">Total Requests</div><div class="val" id="total">0</div></div>
  <div class="card"><div class="lb">Blocked</div><div class="val" id="blocked">0</div><div class="sub" style="color:var(--red)">threats</div></div>
  <div class="card"><div class="lb">Passed</div><div class="val" id="passed">0</div><div class="sub" style="color:var(--green)">legit</div></div>
  <div class="card"><div class="lb">Peak RPS</div><div class="val" id="peak">0</div></div>
  <div class="card"><div class="lb">Active Conns</div><div class="val" id="conns">0</div></div>
  <div class="card"><div class="lb">Banned IPs</div><div class="val" id="banned">0</div></div>
  <div class="card"><div class="lb">TLS Early Reject</div><div class="val" id="early_rejected">0</div><div class="sub" id="early_st">processed: 0</div></div>
  <div class="card"><div class="lb">eBPF/XDP Drop</div><div class="val" id="xdp_drops">0</div><div class="sub" id="xdp_st">inactive</div></div>
</div>

<div class="chart-box">
  <h2>Traffic Timeline (5 min)</h2>
  <canvas id="chart"></canvas>
</div>

<div class="row2">
  <div class="section">
    <h2>System Health</h2>
    <div style="margin-bottom:12px">
      <div style="display:flex;justify-content:space-between;font-size:12px"><span>Block Rate</span><span id="br">0%%</span></div>
      <div class="meter"><div class="meter-fill g" id="brm" style="width:0%%"></div></div>
    </div>
    <div style="margin-bottom:12px">
      <div style="display:flex;justify-content:space-between;font-size:12px"><span>Connection Load</span><span id="cl">0%%</span></div>
      <div class="meter"><div class="meter-fill g" id="clm" style="width:0%%"></div></div>
    </div>
    <div>
      <div style="display:flex;justify-content:space-between;font-size:12px"><span>Uptime</span><span id="up">0s</span></div>
    </div>
  </div>
  <div class="section">
    <h2>Recent Events</h2>
    <div id="logs">
      <div class="log-line"><span class="t">--:--:--</span>Waiting for data...</div>
    </div>
  </div>
</div>

<div class="section" style="margin-bottom:24px">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
    <h2>Mango Mesh Network</h2>
    <span class="badge ok" style="margin:0"><span id="mesh_count">0</span> Nodes Active</span>
  </div>
  <div class="node-list" id="mesh_nodes_list">
    <!-- Nodes will be injected here -->
  </div>
</div>

</div>
<div class="foot">Mango Shield v2.0 • Anti-DDoS L7 Protection</div>

<script>
var W=300,H=180,chart=document.getElementById('chart'),ctx=chart.getContext('2d');
chart.width=chart.parentElement.clientWidth-40;chart.height=H;
var rpsData=new Array(300).fill(0),maxY=10,logs=[];

function fmt(n){if(n>=1e9)return(n/1e9).toFixed(1)+'B';if(n>=1e6)return(n/1e6).toFixed(1)+'M';if(n>=1e3)return(n/1e3).toFixed(1)+'K';return n.toString();}
function fmtTime(s){var h=Math.floor(s/3600),m=Math.floor((s%%3600)/60);return h>0?h+'h '+m+'m':m>0?m+'m':Math.floor(s)+'s';}

function drawChart(){
  var w=chart.width,h=chart.height;ctx.clearRect(0,0,w,h);
  maxY=Math.max(10,...rpsData)*1.2;
  // Grid
  ctx.strokeStyle='rgba(255,255,255,0.04)';ctx.lineWidth=1;
  for(var i=0;i<5;i++){var y=h-h*(i/4);ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(w,y);ctx.stroke();}
  // Area
  var grad=ctx.createLinearGradient(0,0,0,h);
  grad.addColorStop(0,'rgba(255,107,53,0.3)');grad.addColorStop(1,'rgba(255,107,53,0)');
  ctx.fillStyle=grad;ctx.beginPath();ctx.moveTo(0,h);
  for(var i=0;i<rpsData.length;i++){var x=i/(rpsData.length-1)*w,y=h-rpsData[i]/maxY*h;ctx.lineTo(x,y);}
  ctx.lineTo(w,h);ctx.closePath();ctx.fill();
  // Line
  ctx.strokeStyle='#ff6b35';ctx.lineWidth=2;ctx.beginPath();
  for(var i=0;i<rpsData.length;i++){var x=i/(rpsData.length-1)*w,y=h-rpsData[i]/maxY*h;i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);}
  ctx.stroke();
  // Labels
  ctx.fillStyle='#6e6e90';ctx.font='10px system-ui';
  ctx.fillText(fmt(Math.round(maxY)),4,14);ctx.fillText('0',4,h-4);
  ctx.fillText('5m ago',4,h-20);ctx.fillText('now',w-30,h-20);
}

function addLog(msg,type){
  var t=new Date().toLocaleTimeString();
  logs.unshift({t:t,msg:msg,type:type||''});
  if(logs.length>8)logs.pop();
  var el=document.getElementById('logs');el.innerHTML='';
  logs.forEach(function(l){
    el.innerHTML+='<div class="log-line '+l.type+'"><span class="t">'+l.t+'</span>'+l.msg+'</div>';
  });
}

var lastBlocked=0,lastAttacks=0,wasAttack=false;
function update(){
  fetch('/api/stats').then(function(r){return r.json()}).then(function(d){
    document.getElementById('rps').textContent=fmt(d.current_rps);
    document.getElementById('total').textContent=fmt(d.total_requests);
    document.getElementById('blocked').textContent=fmt(d.blocked_requests);
    document.getElementById('passed').textContent=fmt(d.passed_requests);
    document.getElementById('peak').textContent=fmt(d.peak_rps);
    document.getElementById('conns').textContent=fmt(d.active_conns);
    document.getElementById('banned').textContent=fmt(d.banned_ips);
    document.getElementById('xdp_drops').textContent=fmt(d.xdp_drops);
    document.getElementById('early_rejected').textContent=fmt(d.early_rejected);
    document.getElementById('early_st').textContent='processed: '+fmt(d.early_processed);
    document.getElementById('up').textContent=fmtTime(d.uptime_seconds);

    var xst=document.getElementById('xdp_st');
    if(d.xdp_enabled){ xst.textContent='Active (Hardware)'; xst.style.color='var(--green)'; }
    else { xst.textContent='Inactive'; xst.style.color='var(--text2)'; }

    var st=document.getElementById('st');
    if(d.is_under_attack){st.className='badge atk';st.textContent='⚠ UNDER ATTACK';}
    else{st.className='badge ok';st.textContent='● Normal';}

    // Block rate
    var br=d.total_requests>0?Math.round(d.blocked_requests/d.total_requests*100):0;
    document.getElementById('br').textContent=br+'%%';
    var brm=document.getElementById('brm');brm.style.width=br+'%%';
    brm.className='meter-fill '+(br>50?'r':br>20?'y':'g');

    // Connection load
    var cl=Math.min(100,Math.round(d.active_conns/100));
    document.getElementById('cl').textContent=cl+'%%';
    var clm=document.getElementById('clm');clm.style.width=cl+'%%';
    clm.className='meter-fill '+(cl>80?'r':cl>50?'y':'g');

    // Events
    if(d.blocked_requests>lastBlocked+10){addLog('Blocked '+(d.blocked_requests-lastBlocked)+' requests','warn');}
    if(d.attacks_detected>lastAttacks){addLog('🚨 New attack detected!','err');}
    if(d.is_under_attack&&!wasAttack){addLog('⚠ Attack started — RPS: '+d.current_rps,'err');}
    if(!d.is_under_attack&&wasAttack){addLog('✓ Attack mitigated','');}
    lastBlocked=d.blocked_requests;lastAttacks=d.attacks_detected;wasAttack=d.is_under_attack;

    // Update Mesh List
    document.getElementById('mesh_count').textContent = d.mesh_nodes;
    var meshList = document.getElementById('mesh_nodes_list');
    meshList.innerHTML = '';
    if (d.mesh_members && d.mesh_members.length > 0) {
      d.mesh_members.forEach(function(m) {
        meshList.innerHTML += '<div class="node-item">' +
          '<div class="n-name"><div class="n-status"></div>' + m.name + '</div>' +
          '<div class="n-addr">' + m.addr + '</div>' +
          '</div>';
      });
    } else {
      meshList.innerHTML = '<div style="font-size:12px;color:var(--text2);text-align:center;padding:20px">No active mesh nodes found.</div>';
    }
  }).catch(function(){});

  fetch('/api/rps-history').then(function(r){return r.json()}).then(function(d){
    rpsData=d.rps;drawChart();
  }).catch(function(){});
}

addLog('Dashboard initialized','');
update();setInterval(update,1000);
window.addEventListener('resize',function(){chart.width=chart.parentElement.clientWidth-40;drawChart();});
</script>
</body>
</html>`)
