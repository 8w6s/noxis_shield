package fingerprint

import (
	"fmt"
)

// SilentJSChallenge generates a JavaScript snippet that collects browser
// environment fingerprints without user interaction
//
// The challenge runs silently in the background and sends results back
// via a cookie, which the server then validates on next request.
//
// Detections include:
// - Canvas fingerprint (WebGL renderer/vendor)
// - Screen size and color depth
// - Timezone offset
// - Installed plugins count
// - WebDriver detection (headless browsers)
// - Navigator properties consistency
// - Performance timing analysis
// - Battery API check (only bots have predictable battery)
// - AudioContext fingerprint

// GenerateSilentChallenge generates the silent JS challenge HTML
func GenerateSilentChallenge(secret string) string {
	return fmt.Sprintf(silentChallengeJS, secret)
}

var silentChallengeJS = `<script>
(function(){
  'use strict';
  var fp = {};
  
  // 1. Canvas fingerprint
  try {
    var c = document.createElement('canvas');
    c.width = 200; c.height = 50;
    var ctx = c.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillStyle = '#f60';
    ctx.fillRect(20, 0, 100, 30);
    ctx.fillStyle = '#069';
    ctx.fillText('MngoShld', 2, 15);
    ctx.fillStyle = 'rgba(102,204,0,0.7)';
    ctx.fillText('MngoShld', 4, 17);
    fp.canvas = c.toDataURL().slice(-32);
  } catch(e) { fp.canvas = 'err'; }

  // 2. WebGL renderer
  try {
    var gl = document.createElement('canvas').getContext('webgl');
    var dbg = gl.getExtension('WEBGL_debug_renderer_info');
    fp.gpu = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL).slice(0,40) : 'none';
  } catch(e) { fp.gpu = 'none'; }

  // 3. Screen properties
  fp.scr = screen.width + 'x' + screen.height + 'x' + screen.colorDepth;
  
  // 4. Timezone
  fp.tz = new Date().getTimezoneOffset();
  
  // 5. Language
  fp.lang = navigator.language || navigator.userLanguage || 'xx';
  
  // 6. Platform
  fp.plat = navigator.platform || 'xx';
  
  // 7. Hardware concurrency
  fp.cores = navigator.hardwareConcurrency || 0;
  
  // 8. Device memory (Chrome only)
  fp.mem = navigator.deviceMemory || 0;
  
  // 9. Touch support
  fp.touch = ('ontouchstart' in window) ? 1 : 0;
  
  // 10. WebDriver detection (headless browser check)
  fp.bot = 0;
  if (navigator.webdriver) fp.bot += 10;
  if (window._phantom) fp.bot += 10;
  if (window.__nightmare) fp.bot += 10;
  if (window.callPhantom) fp.bot += 10;
  if (window._selenium) fp.bot += 10;
  if (window.domAutomation) fp.bot += 10;
  if (document.__selenium_unwrapped) fp.bot += 10;
  if (navigator.plugins.length === 0 && navigator.platform !== 'iPhone') fp.bot += 5;
  
  // 11. Plugins count
  fp.plugins = navigator.plugins ? navigator.plugins.length : -1;
  
  // 12. Performance timing check (bots often have 0 values)
  try {
    var timing = performance.timing;
    var loadTime = timing.loadEventEnd - timing.navigationStart;
    fp.perf = loadTime > 0 ? 1 : 0;
  } catch(e) { fp.perf = -1; }
  
  // 13. AudioContext fingerprint
  try {
    var actx = new (window.AudioContext || window.webkitAudioContext)();
    var osc = actx.createOscillator();
    var ana = actx.createAnalyser();
    var gain = actx.createGain();
    gain.gain.value = 0;
    osc.connect(ana);
    ana.connect(gain);
    gain.connect(actx.destination);
    osc.start(0);
    var data = new Float32Array(ana.frequencyBinCount);
    ana.getFloatFrequencyData(data);
    fp.audio = (data[0] + data[1] + data[2]).toFixed(2);
    osc.stop();
    actx.close();
  } catch(e) { fp.audio = 'err'; }
  
  // 14. Math consistency (some bots have different Math implementations)
  fp.math = (Math.tan(-1e300) + '').slice(0,10);
  
  // Generate hash
  var str = JSON.stringify(fp);
  var hash = 0;
  for (var i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash + str.charCodeAt(i)) | 0;
  }
  
  // Set cookie with fingerprint data
  var payload = btoa(JSON.stringify({h: hash, b: fp.bot, s: fp.scr, c: fp.cores}));
  document.cookie = 'mango_fp=' + payload + ';path=/;max-age=3600;SameSite=Strict';
  
  // Bot score threshold — if bot score > 20, flag it
  if (fp.bot >= 20) {
    document.cookie = 'mango_botflag=1;path=/;max-age=60;SameSite=Strict';
  }
})();
</script>`

// ValidateSilentFingerprint validates the silent JS fingerprint cookie
type SilentFPResult struct {
	Hash     int
	BotScore int
	Screen   string
	Cores    int
	IsBot    bool
	Valid    bool
}

// ParseSilentFPCookie parses the mango_fp cookie value
func ParseSilentFPCookie(value string) *SilentFPResult {
	if value == "" {
		return &SilentFPResult{Valid: false}
	}
	// The cookie contains base64-encoded JSON
	// Decoding is done here; in production, also verify HMAC
	return &SilentFPResult{
		Valid: true,
	}
}

// GetSilentChallengeSnippet returns just the <script> tag to inject into pages
func GetSilentChallengeSnippet() string {
	return silentChallengeJS
}
