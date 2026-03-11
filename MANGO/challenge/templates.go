package challenge

// powTemplate is the modern JS Proof-of-Work challenge page with Web Worker
var powTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Check — Mango Shield</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0b10;--card:rgba(18,18,30,0.85);--border:rgba(255,107,53,0.15);--accent:#ff6b35;--accent2:#f7c948;--text:#e0e0e8;--text2:#8080a0;--glow:rgba(255,107,53,0.3)}
@keyframes fadeIn{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
@keyframes pulse{0%%,100%%{opacity:1}50%%{opacity:0.5}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes progress{from{width:0}to{width:100%%}}
@keyframes glow{0%%,100%%{box-shadow:0 0 20px var(--glow)}50%%{box-shadow:0 0 40px var(--glow)}}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,-apple-system,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;overflow:hidden}
body::before{content:'';position:fixed;top:-50%%;left:-50%%;width:200%%;height:200%%;background:radial-gradient(circle at 30%% 50%%,rgba(255,107,53,0.03),transparent 50%%),radial-gradient(circle at 70%% 60%%,rgba(247,201,72,0.02),transparent 50%%);z-index:0}
.container{position:relative;z-index:1;text-align:center;animation:fadeIn 0.6s ease-out}
.card{background:var(--card);border:1px solid var(--border);border-radius:20px;padding:48px 40px;backdrop-filter:blur(20px);max-width:440px;width:90vw;animation:glow 3s infinite}
.shield{font-size:56px;margin-bottom:16px;display:block}
h1{font-size:22px;font-weight:600;margin-bottom:8px;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.sub{color:var(--text2);font-size:14px;margin-bottom:32px;line-height:1.5}
.progress-wrap{background:rgba(255,255,255,0.05);border-radius:12px;height:8px;overflow:hidden;margin-bottom:16px;position:relative}
.progress-bar{height:100%%;background:linear-gradient(90deg,var(--accent),var(--accent2));border-radius:12px;width:0%%;transition:width 0.3s ease}
.status{font-size:13px;color:var(--text2);margin-bottom:24px;min-height:20px}
.spinner{display:inline-block;width:18px;height:18px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%%;animation:spin 0.8s linear infinite;vertical-align:middle;margin-right:8px}
.stats{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:24px}
.stat{background:rgba(255,255,255,0.03);border-radius:10px;padding:12px}
.stat-label{font-size:11px;color:var(--text2);text-transform:uppercase;letter-spacing:0.5px}
.stat-value{font-size:18px;font-weight:700;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-top:4px}
.success{color:#00d68f}
.footer{margin-top:24px;font-size:11px;color:var(--text2)}
.footer a{color:var(--accent);text-decoration:none}
</style>
</head>
<body>
<div class="container">
<div class="card">
  <span class="shield">🛡️</span>
  <h1>Checking Your Browser</h1>
  <p class="sub">This process is automatic. Your browser will be verified in a moment.</p>
  <div class="progress-wrap"><div class="progress-bar" id="pbar"></div></div>
  <div class="status" id="status"><span class="spinner"></span>Initializing security check...</div>
  <div class="stats">
    <div class="stat"><div class="stat-label">Hashes</div><div class="stat-value" id="hashes">0</div></div>
    <div class="stat"><div class="stat-label">Speed</div><div class="stat-value" id="speed">—</div></div>
  </div>
  <div class="footer">Protected by <a href="#">Mango Shield</a> v2.0</div>
</div>
</div>
<script>
(function(){
  var challenge='%s',difficulty=%d,target=%d,redir='%s';
  var prefix='';for(var i=0;i<target;i++)prefix+='0';
  var startTime=Date.now(),hashCount=0,found=false;
  var statusEl=document.getElementById('status');
  var pbar=document.getElementById('pbar');
  var hashesEl=document.getElementById('hashes');
  var speedEl=document.getElementById('speed');

  function fmt(n){if(n>=1e6)return(n/1e6).toFixed(1)+'M';if(n>=1e3)return(n/1e3).toFixed(1)+'K';return n.toString();}

  // Check for secure context (required for crypto.subtle)
  if (!window.isSecureContext) {
    statusEl.innerHTML = '<span style="color:#ff4b4b">⚠️ Error: Secure context required (HTTPS).</span>';
    return;
  }
  if (!window.Worker || !window.crypto || !window.crypto.subtle) {
    statusEl.innerHTML = '<span style="color:#ff4b4b">⚠️ Error: Browser not supported.</span>';
    return;
  }

  // Use Web Worker for PoW computation
  var workerCode='self.onmessage=function(e){var c=e.data.challenge,p=e.data.prefix,s=e.data.start,batch=10000;'+
    'function sha256(m){var buf=new TextEncoder().encode(m);return crypto.subtle.digest("SHA-256",buf);}'+
    'async function solve(){try{for(var i=s;i<s+batch;i++){var h=await sha256(c+i);var a=new Uint8Array(h);'+
    'var hex="";for(var j=0;j<a.length;j++)hex+=("0"+a[j].toString(16)).slice(-2);'+
    'if(hex.startsWith(p)){self.postMessage({found:true,nonce:i.toString(),hash:hex,count:i-s+1});return;}}'+
    'self.postMessage({found:false,count:batch,next:s+batch});}catch(err){self.postMessage({error:err.message});}}solve();};';

  var blob=new Blob([workerCode],{type:'application/javascript'});
  var worker;
  try {
    worker=new Worker(URL.createObjectURL(blob));
  } catch (err) {
    statusEl.innerHTML = '<span style="color:#ff4b4b">⚠️ Error: Failed to start security worker.</span>';
    return;
  }
  var totalCount=0;

  worker.onerror=function(e){
    statusEl.innerHTML = '<span style="color:#ff4b4b">⚠️ Security check failed to initialize.</span>';
  };

  worker.onmessage=function(e){
    var d=e.data;
    if(d.error){
       statusEl.innerHTML = '<span style="color:#ff4b4b">⚠️ Error: '+d.error+'</span>';
       return;
    }
    totalCount+=d.count||0;
    hashCount=totalCount;
    var elapsed=(Date.now()-startTime)/1000;
    var hps=Math.round(hashCount/elapsed);
    hashesEl.textContent=fmt(hashCount);
    speedEl.textContent=fmt(hps)+'/s';
    pbar.style.width=Math.min(95,Math.log(hashCount+1)/Math.log(1e7)*100)+'%%';

    if(d.found){
      pbar.style.width='100%%';
      statusEl.innerHTML='<span class="success">✓ Verified successfully!</span>';
      // Submit solution
      var form=document.createElement('form');form.method='POST';form.action=redir;
      var fields={challenge_type:'pow',nonce:d.nonce,challenge:challenge,difficulty:difficulty.toString()};
      for(var k in fields){var inp=document.createElement('input');inp.type='hidden';inp.name=k;inp.value=fields[k];form.appendChild(inp);}
      document.body.appendChild(form);
      setTimeout(function(){form.submit();},500);
    } else if(d.next!==undefined){
      statusEl.innerHTML='<span class="spinner"></span>Computing proof... '+fmt(hashCount)+' hashes';
      worker.postMessage({challenge:challenge,prefix:prefix,start:d.next});
    }
  };

  worker.postMessage({challenge:challenge,prefix:prefix,start:0});
})();
</script>
</body>
</html>`

// silentTemplate is the invisible JS challenge (browser fingerprinting + auto-redirect)
var silentTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Loading...</title>
<style>body{background:#0a0b10;color:#e0e0e8;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.dot{width:8px;height:8px;border-radius:50%%;background:#ff6b35;margin:0 4px;animation:bounce 1.4s infinite both}
.dot:nth-child(2){animation-delay:0.2s}.dot:nth-child(3){animation-delay:0.4s}
@keyframes bounce{0%%,80%%,100%%{transform:scale(0)}40%%{transform:scale(1)}}</style>
</head>
<body>
<div style="text-align:center">
<div style="display:flex;justify-content:center;margin-bottom:16px">
  <div class="dot"></div><div class="dot"></div><div class="dot"></div>
</div>
<div style="font-size:13px;color:#8080a0">Verifying your connection...</div>
</div>
<script>
(function(){
  var fp={};
  try{var c=document.createElement('canvas');c.width=200;c.height=50;var x=c.getContext('2d');
  x.textBaseline='top';x.font='14px Arial';x.fillStyle='#f60';x.fillRect(20,0,100,30);
  x.fillStyle='#069';x.fillText('Mng',2,15);fp.cv=c.toDataURL().slice(-20);}catch(e){fp.cv='e';}
  try{var g=document.createElement('canvas').getContext('webgl');
  var d=g.getExtension('WEBGL_debug_renderer_info');
  fp.gl=d?g.getParameter(d.UNMASKED_RENDERER_WEBGL).slice(0,30):'n';}catch(e){fp.gl='n';}
  fp.s=screen.width+'x'+screen.height;fp.tz=new Date().getTimezoneOffset();
  fp.c=navigator.hardwareConcurrency||0;fp.l=navigator.language;fp.p=navigator.platform;
  fp.w=navigator.webdriver?1:0;fp.pl=navigator.plugins?navigator.plugins.length:-1;
  var h=0,s=JSON.stringify(fp);for(var i=0;i<s.length;i++)h=((h<<5)-h+s.charCodeAt(i))|0;
  document.cookie='mango_fp='+btoa(JSON.stringify({h:h,w:fp.w,s:fp.s}))+';path=/;max-age=3600;SameSite=Strict';
  if(!fp.w)setTimeout(function(){location.href='%s';},800);
  else document.body.innerHTML='<div style="text-align:center;padding:20px;color:#ff4b4b">Access Denied</div>';
})();
</script>
</body>
</html>`

// captchaTemplate is the Modern Hold-to-Verify UI overlay
var captchaTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Verification — Mango Shield</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0b10;color:#e0e0e8;font-family:-apple-system,system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;margin:0}
.card{background:rgba(18,18,30,0.85);border:1px solid rgba(255,107,53,0.15);border-radius:12px;padding:30px;width:320px;text-align:center;box-shadow:0 8px 32px rgba(0,0,0,0.5)}
.logo{font-size:40px;margin-bottom:20px}
.title{font-size:18px;font-weight:600;margin-bottom:10px}
.desc{font-size:13px;color:#8080a0;margin-bottom:25px;line-height:1.4}
.hold-btn{position:relative;width:100%%;height:54px;background:#1a1a2e;border:1px solid #2a2a4e;border-radius:27px;overflow:hidden;cursor:pointer;user-select:none;touch-action:none;transition:transform 0.1s}
.hold-fill{position:absolute;top:0;left:0;height:100%%;width:0%%;background:linear-gradient(90deg,#ff6b35,#f7c948);transition:width 0.1s linear}
.hold-text{position:absolute;top:0;left:0;width:100%%;height:100%%;display:flex;align-items:center;justify-content:center;font-size:15px;font-weight:600;color:#fff;text-shadow:0 1px 2px rgba(0,0,0,0.5);z-index:2}
.footer{margin-top:20px;font-size:11px;color:#606080}
.footer a{color:#ff6b35;text-decoration:none}
</style>
</head>
<body>
<div class="card">
  <div class="logo">🥭</div>
  <div class="title">Human Verification</div>
  <div class="desc">Please press and hold the button below to confirm you are human.</div>
  
  <div class="hold-btn" id="btn">
     <div class="hold-fill" id="fill"></div>
     <div class="hold-text" id="btnText">Press & Hold</div>
  </div>

  <form id="vform" method="POST" action="%s">
    <input type="hidden" name="challenge_type" value="turnstile">
    <input type="hidden" name="t_id" value="%s">
    <input type="hidden" name="t_hash" value="%s">
    <input type="hidden" name="t_data" id="tData" value="">
  </form>
  <div class="footer">Secured by <a href="#">Mango Shield</a></div>
</div>
<script>
  var btn=document.getElementById('btn'), fill=document.getElementById('fill'), txt=document.getElementById('btnText');
  var form=document.getElementById('vform'), dataInp=document.getElementById('tData');
  var holdTime=0, holding=false, timer, events=[];
  
  function record(e) { if(events.length<10) events.push(e.type); }
  window.addEventListener('mousemove', record);
  window.addEventListener('touchstart', record);

  function startHold(e) {
     if(!e.isTrusted) return; // Anti-Puppeteer basic check
     holding = true;
     btn.style.transform = 'scale(0.96)';
     timer = setInterval(function() {
        holdTime += 50;
        var p = Math.min((holdTime/1500)*100, 100);
        fill.style.width = p + '%%';
        if(holdTime >= 1500) completeHold();
     }, 50);
  }
  function stopHold() {
     if(!holding) return;
     holding = false;
     clearInterval(timer);
     if(holdTime < 1500) { holdTime = 0; fill.style.width = '0%%'; btn.style.transform = 'scale(1)'; }
  }
  function completeHold() {
     clearInterval(timer);
     btn.style.pointerEvents = 'none';
     btn.style.transform = 'scale(1)';
     txt.innerText = 'Verified ✓';
     fill.style.background = '#00d68f';
     
     // Generate an interaction token containing browser entropy
     var ext = (window.screen?screen.width+'x'+screen.height:'0x0') + '|' + (navigator.hardwareConcurrency||0);
     var tok = btoa(events.join(',') + '|' + ext);
     dataInp.value = tok;
     
     setTimeout(function() { form.submit() }, 400);
  }

  btn.addEventListener('mousedown', startHold);
  btn.addEventListener('touchstart', startHold);
  window.addEventListener('mouseup', stopHold);
  window.addEventListener('mouseleave', stopHold);
  window.addEventListener('touchend', stopHold);
  window.addEventListener('touchcancel', stopHold);
</script>
</body>
</html>`
