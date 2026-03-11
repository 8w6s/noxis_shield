import os
import time

# ── FIX MATPLOTLIB THREADING ──
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

import requests
import psutil
import telebot
import io
import threading
import collections
from datetime import datetime

# ── CONFIGURATION — Mango Shield Apex ──
BOT_TOKEN = "6337073929:AAGsvCXWRJ6Ol-K5V1ZCJ6vmcLll-0UsnE8" #token bot telegram
ALLOWED_GROUP_ID = -1001907788832 #id group telegram
NODES = [
    {"name": "Node 1 (.172)", "url": "http://103.77.246.172:9090/api/stats"},
    {"name": "Node 2 (.153)", "url": "http://103.77.246.153:9090/api/stats"}
]
DEFAULT_TARGET = "https://firewall.vutrungocrong.fun/"
API_AUTH = ("admin", "admin123") #user pass admin website ip:9090
TEST_DURATION = 120 #time test dstat

bot = telebot.TeleBot(BOT_TOKEN)

# ── GLOBAL STATE ──
state = {
    "is_testing": False,
    "test_start_time": 0,
    "test_user": None,
    "target_url": DEFAULT_TARGET,
    "rps_history": collections.deque(maxlen=120), 
    "bps_history": collections.deque(maxlen=120),
    "last_net_io": psutil.net_io_counters(),
    "last_check_time": time.time(),
    "baseline": {} 
}

# ── UTILITIES ──
def get_ascii_bar(percent, width=15):
    filled = int(width * percent / 100)
    bar = "█" * filled + "░" * (width - filled)
    return bar

def format_num(num):
    if num is None: return "0"
    if num >= 1_000_000_000: return f"{num/1_000_000_000:.1f}B"
    if num >= 1_000_000: return f"{num/1_000_000:.1f}M"
    if num >= 1_000: return f"{num/1_000:.1f}K"
    return str(num)

# ── STATS COLLECTION ──
def get_stats():
    # Local HW stats (Always from Node 1 where bot runs)
    cpu = psutil.cpu_percent()
    ram = psutil.virtual_memory().percent
    
    now = time.time()
    dt = now - state["last_check_time"]
    if dt <= 0: dt = 0.1
    
    current_net_io = psutil.net_io_counters()
    recv_bps = (current_net_io.bytes_recv - state["last_net_io"].bytes_recv) * 8 / dt
    state["last_net_io"] = current_net_io
    state["last_check_time"] = now
    
    # Aggregate Mango Cluster Stats
    agg = {
        "current_rps": 0, "total_requests": 0, "blocked_requests": 0,
        "passed_requests": 0, "peak_rps": 0, "active_conns": 0,
        "banned_ips": 0, "xdp_drops": 0, "early_rejected": 0,
        "early_processed": 0, "cache_hits": 0, "cache_misses": 0,
        "cache_bypasses": 0, "mesh_nodes": 0, "is_under_attack": False,
        "xdp_enabled": False
    }
    
    online_nodes = 0
    for node in NODES:
        try:
            resp = requests.get(node["url"], auth=API_AUTH, timeout=1.0)
            if resp.status_code == 200:
                d = resp.json()
                online_nodes += 1
                agg["current_rps"] += d.get("current_rps", 0)
                agg["total_requests"] += d.get("total_requests", 0)
                agg["blocked_requests"] += d.get("blocked_requests", 0)
                agg["passed_requests"] += d.get("passed_requests", 0)
                agg["active_conns"] += d.get("active_conns", 0)
                agg["xdp_drops"] += d.get("xdp_drops", 0)
                agg["early_rejected"] += d.get("early_rejected", 0)
                agg["early_processed"] += d.get("early_processed", 0)
                agg["cache_hits"] += d.get("cache_hits", 0)
                agg["cache_misses"] += d.get("cache_misses", 0)
                agg["cache_bypasses"] += d.get("cache_bypasses", 0)
                agg["peak_rps"] = max(agg["peak_rps"], d.get("peak_rps", 0))
                agg["banned_ips"] = max(agg["banned_ips"], d.get("banned_ips", 0)) # Gossip shared
                agg["mesh_nodes"] = max(agg["mesh_nodes"], d.get("mesh_nodes", 0))
                if d.get("is_under_attack"): agg["is_under_attack"] = True
                if d.get("xdp_enabled"): agg["xdp_enabled"] = True
        except:
            pass
            
    agg["node_count"] = online_nodes
    rps = agg["current_rps"]
    mbps = recv_bps / 1024 / 1024
    
    state["rps_history"].append(rps)
    state["bps_history"].append(mbps)
    
    return {
        "cpu": cpu, "ram": ram, "mbps": mbps,
        "mango": agg, "timestamp": datetime.now().strftime("%H:%M:%S")
    }

# ── CHART GENERATION ──
def generate_chart():
    fig = plt.figure(figsize=(10, 4.5))
    plt.style.use('dark_background')
    
    x = range(len(state["rps_history"]))
    y = list(state["rps_history"])
    
    plt.plot(x, y, color='#ff6b35', label='Requests/Sec', linewidth=2.5, marker='o', markevery=[-1], markersize=6)
    plt.fill_between(x, y, color='#ff6b35', alpha=0.15)
    
    plt.title(f"Target: {state['target_url']}", color='#f7c948', fontsize=14, fontweight='bold', pad=15)
    plt.ylabel("RPS", color='#e0e0f0')
    plt.xlabel("Seconds", color='#e0e0f0')
    plt.grid(color='#1c1c3a', linestyle='-', linewidth=0.5, alpha=0.5)
    
    if y and max(y) > 0:
        plt.ylim(0, max(y) * 1.3)
    else:
        plt.ylim(0, 100)
        
    plt.legend(loc='upper left', frameon=False)
    
    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight', dpi=100)
    plt.close(fig)
    buf.seek(0)
    return buf

# ── MESSAGE FORMATTING — FULL FIDELITY VERSION ──
def format_testing_msg(s_stats, remaining):
    m = s_stats["mango"] or {}
    b = state["baseline"]
    
    def get_session_val(key):
        return max(0, int(m.get(key, 0)) - int(b.get(key, 0)))

    # Session Delta Stats
    session_total = get_session_val("total_requests")
    session_blocked = get_session_val("blocked_requests")
    session_passed = get_session_val("passed_requests")
    session_xdp = get_session_val("xdp_drops")
    session_early_rej = get_session_val("early_rejected")
    session_early_proc = get_session_val("early_processed")
    
    # Global/Live Stats
    session_peak = max(list(state["rps_history"]) + [0])
    is_atk = m.get("is_under_attack", False)
    status = "🚨 UNDER ATTACK" if is_atk else "✅ SECURED (AUTO)"
    
    # XDP Hardware Status
    xdp_st = "Active (Hardware)" if m.get("xdp_enabled") else "Inactive"
    
    # Cache Stats
    hits = m.get("cache_hits", 0)
    misses = m.get("cache_misses", 0)
    bypasses = m.get("cache_bypasses", 0)
    total_cache = hits + misses + bypasses
    hit_rate = (hits / total_cache * 100) if total_cache > 0 else 0

    # ASCII Progress
    p_width = 15
    p_done = int(p_width * (120 - remaining) / 120)
    p_bar = "▰" * p_done + "▱" * (p_width - p_done)

    msg = (
        f"👑 <b>MANGO DSTAT PRO MAX — FIDELITY</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"🎯 <b>Target:</b> <code>{state['target_url']}</code>\n"
        f"👤 <b>Tester:</b> @{state['test_user']}\n"
        f"⏳ <b>Prog:</b> <code>[{p_bar}] {remaining}s</code>\n\n"
        
        f"📊 <b>INTELLIGENCE PANEL (DASHBOARD):</b>\n"
        f"🌐 <b>Status:</b> <b>{status}</b>\n"
        f"📈 <b>Current RPS:</b> <code>{format_num(m.get('current_rps'))}</code> /s\n"
        f"🔝 <b>Session Peak:</b> <code>{format_num(session_peak)}</code>\n"
        f"📑 <b>Session Req:</b> <code>{format_num(session_total)}</code>\n"
        f"🚫 <b>Blocked:</b> <code>{format_num(session_blocked)}</code> (Threats)\n"
        f"✅ <b>Passed:</b> <code>{format_num(session_passed)}</code> (Legit)\n\n"
        
        f"🛡️ <b>SECURITY ACTIONS:</b>\n"
        f"⚡ <b>Active Conns:</b> <code>{format_num(m.get('active_conns'))}</code>\n"
        f"🔨 <b>Banned IPs:</b> <code>{format_num(m.get('banned_ips'))}</code>\n"
        f"� <b>TLS Reject:</b> <code>{format_num(session_early_rej)}</code>\n"
        f"   └ <i>processed: {format_num(session_early_proc)}</i>\n"
        f"🔥 <b>eBPF/XDP Drop:</b> <code>{format_num(session_xdp)}</code>\n"
        f"   └ <i>{xdp_st}</i>\n"
        f"💎 <b>Cache Hit Rate:</b> <code>{hit_rate:.1f}%</code>\n\n"
        
        f"🖥 <b>HARDWARE PERFORMANCE:</b>\n"
        f"• <b>CPU:</b> <code>[{get_ascii_bar(s_stats['cpu'])}] {s_stats['cpu']}%</code>\n"
        f"• <b>RAM:</b> <code>[{get_ascii_bar(s_stats['ram'])}] {s_stats['ram']}%</code>\n"
        f"• <b>NET:</b> <code>{s_stats['mbps']:.2f} Mbps (In)</code>\n\n"
        
        f"🔗 <b>Mesh:</b> <code>{m.get('mesh_nodes', 1)} Nodes Online</code>\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"📡 <i>Updating: Text 4s | Chart 20s</i>"
    )
    return msg

# ── COMMAND HANDLERS ──
@bot.message_handler(commands=['start', 'help'])
def handle_start_help(message):
    if message.chat.id != ALLOWED_GROUP_ID: return
    help_text = (
        f"🥭 <b>MANGO DSTAT PRO MAX - FULL FIDELITY</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"🚀 <b>Các lệnh chính:</b>\n"
        f"• <code>/test</code> - Đo lường Website: {DEFAULT_TARGET}\n"
        f"• <code>/status</code> - Xem tình trạng server hiện tại.\n"
        f"• <code>/help</code> - Hướng dẫn sử dụng.\n\n"
        f"💎 <b>Đặc điểm:</b> Hiển thị 100% chỉ số Dashboard, bao gồm TLS processed và XDP Hardware Status.\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"Gõ <code>/test</code> để bắt đầu!"
    )
    bot.reply_to(message, help_text, parse_mode="HTML")

@bot.message_handler(commands=['test'])
def handle_test(message):
    if message.chat.id != ALLOWED_GROUP_ID: return

    if state["is_testing"]:
        passed = int(time.time() - state["test_start_time"])
        rem = TEST_DURATION - passed
        bot.reply_to(message, f"⚠️ <b>Hệ thống đang bận!</b>\nNgười dùng @{state['test_user']} đang test.\nCòn lại <code>{rem}s</code>.", parse_mode="HTML")
        return

    if state["is_testing"]:
        passed = int(time.time() - state["test_start_time"])
        rem = TEST_DURATION - passed
        bot.reply_to(message, f"⚠️ <b>Hệ thống đang bận!</b>\nNgười dùng @{state['test_user']} đang test.\nCòn lại <code>{rem}s</code>.", parse_mode="HTML")
        return

    # Clear baseline and fetch from all nodes
    agg_baseline = {
        "total_requests": 0, "blocked_requests": 0, "passed_requests": 0,
        "xdp_drops": 0, "early_rejected": 0, "early_processed": 0
    }
    for node in NODES:
        try:
            resp = requests.get(node["url"], auth=API_AUTH, timeout=2.0)
            if resp.status_code == 200:
                d = resp.json()
                for key in agg_baseline:
                    agg_baseline[key] += d.get(key, 0)
        except:
            pass
    state["baseline"] = agg_baseline

    args = message.text.split()
    target = DEFAULT_TARGET
    # Fixed target only, no URL args needed
            
    state["is_testing"] = True
    state["test_start_time"] = time.time()
    state["test_user"] = message.from_user.username or message.from_user.first_name
    state["target_url"] = target
    state["rps_history"].clear()
    state["bps_history"].clear()

    s_stats = get_stats()
    chart = generate_chart()
    try:
        sent_msg = bot.send_photo(
            message.chat.id, 
            chart, 
            caption=format_testing_msg(s_stats, TEST_DURATION), 
            parse_mode="HTML"
        )
        threading.Thread(target=test_loop, args=(message.chat.id, sent_msg.message_id)).start()
    except Exception as e:
        print(f"Error starting test: {e}")
        state["is_testing"] = False

def test_loop(chat_id, msg_id):
    last_text_update = 0
    last_chart_update = 0
    
    while True:
        now = time.time()
        passed = int(now - state["test_start_time"])
        remaining = TEST_DURATION - passed
        
        if remaining <= 0: break
            
        if now - last_text_update >= 4:
            s_stats = get_stats()
            
            if now - last_chart_update >= 20:
                chart = generate_chart()
                try:
                    bot.edit_message_media(
                        media=telebot.types.InputMediaPhoto(chart, caption=format_testing_msg(s_stats, remaining), parse_mode="HTML"),
                        chat_id=chat_id,
                        message_id=msg_id
                    )
                    last_chart_update = now
                except Exception as e:
                    if "Too Many Requests" in str(e): time.sleep(10)
                    print(f"Chart update err: {e}")
            else:
                try:
                    bot.edit_message_caption(
                        caption=format_testing_msg(s_stats, remaining),
                        chat_id=chat_id,
                        message_id=msg_id,
                        parse_mode="HTML"
                    )
                except Exception as e:
                    if "Too Many Requests" in str(e): time.sleep(5)
                    print(f"Text update err: {e}")
            
            last_text_update = now
            
        time.sleep(1)

    state["is_testing"] = False
    s_stats = get_stats()
    m = s_stats["mango"] or {}
    b = state["baseline"]
    
    final_peak = max(list(state["rps_history"]) + [0])
    block_delta = max(0, int(m.get("blocked_requests", 0)) - int(b.get("blocked_requests", 0)))
    pass_delta = max(0, int(m.get("passed_requests", 0)) - int(b.get("passed_requests", 0)))
    total_delta = max(0, int(m.get("total_requests", 0)) - int(b.get("total_requests", 0)))
    xdp_delta = max(0, int(m.get("xdp_drops", 0)) - int(b.get("xdp_drops", 0)))
    tls_delta = max(0, int(m.get("early_rejected", 0)) - int(b.get("early_rejected", 0)))

    final_msg = (
        f"✅ <b>MANGO MISSION — COMPLETED</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"🎯 <b>Target:</b> <code>{state['target_url']}</code>\n"
        f"👤 <b>Tester:</b> @{state['test_user']}\n\n"
        f"💎 <b>SESSION SUMMARY:</b>\n"
        f"• <b>Peak Performance:</b> <code>{format_num(final_peak)} RPS</code>\n"
        f"• <b>Total Requests:</b> <code>{format_num(total_delta)}</code>\n"
        f"• <b>Blocked (WAF/L7):</b> <code>{format_num(block_delta)}</code>\n"
        f"• <b>Passed (Legit):</b> <code>{format_num(pass_delta)}</code>\n"
        f"• <b>XDP Hardware Drop:</b> <code>{format_num(xdp_delta)}</code>\n"
        f"• <b>TLS Early Reject:</b> <code>{format_num(tls_delta)}</code>\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"Sẵn sàng cho nhiệm vụ tiếp theo! 🥭🚀"
    )
    try:
        bot.send_message(chat_id, final_msg, parse_mode="HTML")
    except: pass

@bot.message_handler(commands=['status'])
def handle_status(message):
    if message.chat.id != ALLOWED_GROUP_ID: return
    s = get_stats()
    m = s["mango"] or {}
    msg = (
        f"📡 <b>MANGO STATUS PANEL</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"🚀 <b>Live RPS:</b> <code>{format_num(m.get('current_rps'))}</code>\n"
        f"🔝 <b>Global Peak:</b> <code>{format_num(m.get('peak_rps'))}</code>\n"
        f"🔒 <b>Total Banned:</b> <code>{format_num(m.get('banned_ips'))}</code>\n"
        f"🖥 <b>CPU/RAM:</b> <code>{s['cpu']}% / {s['ram']}%</code>\n"
        f"🔗 <b>Mesh:</b> <code>{m.get('mesh_nodes', 1)} Nodes</code>\n"
        f"━━━━━━━━━━━━━━━━━━━━━"
    )
    bot.reply_to(message, msg, parse_mode="HTML")

if __name__ == "__main__":
    print("Mango DStat Pro Max Full Fidelity started...")
    bot.infinity_polling(timeout=60, long_polling_timeout=60)
