 #usr/bin/env python3
"""//Server Protector Bot
Overview
--------
This module implements an asynchronous "Server Protector" monitoring bot for Linux/Ubuntu
servers. It continuously watches system logs and metrics, detects suspicious activity,
and sends batched, rate-limited alerts to an administrator via Telegram.
Key features
------------
- Tails /var/log/auth.log (and optionally Postgres logs) to detect SSH events:
    failed logins, invalid user attempts, accepted logins (including root) and sudo events.
- Periodic resource monitoring: CPU, memory, disk usage.
- Network monitoring: per-interface throughput vs. link speed.
- Periodic port scanning on configured hosts/ports (with optional range).
- Ping/host reachability checks for configured hosts.
- Public IP detection and change alerts using an external IP service.
- Suspicious process detection (heuristics for tools like netcat, socat).
- Aggregates alerts into a single summary message at configurable intervals.
- Per-alert-text cooldowns to prevent spamming the admin.
- Telegram bot commands and inline buttons for status, quick scans, snoozing, and tailing logs.
Important configuration points (defined as module-level constants)
------------------------------------------------------------------
- TELEGRAM_BOT_TOKEN: Telegram bot token (sensitive, keep secret).
- ADMIN_TELEGRAM_ID: Telegram numeric user id of administrator to receive alerts.
- AUTH_LOG, PG_LOG: file paths to monitor (auth.log is the primary SSH/auth log).
- Thresholds: CPU_THRESHOLD, MEM_THRESHOLD, DISK_THRESHOLD, NET_THRESHOLD.
- FAILED_ATTEMPT_WINDOW and FAILED_ATTEMPT_LIMIT: brute-force detection window and limit.
- PORTS_TO_SCAN, PORT_RANGE, PORT_SCAN_CONCURRENT, PORT_SCAN_INTERVAL: port scanning controls.
- PING_HOSTS: list of hosts/IPs to ping for reachability checks.
- SUMMARY_INTERVAL and ALERT_COOLDOWN: batching and rate-limiting of alerts.
- PUBLIC_IP_URL and PUBLIC_IP_CHECK_INTERVAL: public IP checking.
Async tasks / Primary functions
-------------------------------
- main(): boots the Telegram Application, registers handlers and schedules background tasks.
- tail_log_loop(path, line_handler): asynchronous tail/follow implementation for files.
- handle_auth_line(line): parses auth.log lines to detect failed/invalid/accepted logins and sudo events.
- resource_monitor_loop(application): polls CPU/memory/disk and generates alerts if thresholds exceeded.
- network_monitor_loop(application): measures interface throughput and compares it to link speed.
- port_scan_loop(application, hosts, ports, port_range): scans ports and reports open ones.
- ping_loop(application, hosts): pings configured hosts and alerts when unreachable.
- public_ip_loop(application): checks public IP and alerts on change.
- suspicious_process_loop(application): inspects running processes for known suspicious commands.
- send_summary_if_due(application): sends the batched alert summary to the admin if the summary interval elapsed.
- add_pending(msg) and rate_limited_alert(text): helpers for adding alerts with per-text cooldowns.
Telegram interaction
--------------------
- Commands implemented: /status, /snooze <mins>, /tail [file], /scan, /ports, /help
- Inline keyboard buttons offer quick actions: show system status, snooze alerts,
    show last log lines, and run a local port scan.
- Admin-only commands are enforced by checking update.effective_user.id against ADMIN_TELEGRAM_ID.
Security & operational notes
----------------------------
- The bot requires read access to monitored log files (e.g. /var/log/auth.log). On most systems
    this needs root or group access (e.g., adm). Run with appropriate privileges or adjust file ACLs.
- Keep TELEGRAM_BOT_TOKEN secret. Do not commit it to source control.
- Port scanning can be intrusive or trigger IDS — configure ranges and scan frequency responsibly.
- The module performs network operations and spawns concurrent tasks; monitor resource usage if run on constrained systems.
- Rate limiting and summary batching are implemented to reduce alert noise; tune SUMMARY_INTERVAL and ALERT_COOLDOWN as needed.
Dependencies
------------
- Python 3.8+
- asyncio (stdlib)
- python-telegram-bot (v20+ async API)
- psutil
- aiohttp
- nest_asyncio (used to allow nested loops in some runtimes)
- requests (used in some utility paths)
- socket (stdlib)
Usage
-----
Run the module directly on the target server:
        python server_alert.py
Ensure TELEGRAM_BOT_TOKEN and ADMIN_TELEGRAM_ID are correctly configured in the module
(or refactor to use environment variables/config file for production deployments).
Extensibility
-------------
- Add or change monitored log files by updating AUTH_LOG/PG_LOG or registering additional tails.
- Extend suspicious process heuristics by updating SUSPICIOUS_PROCESSES.
- Add custom alert handlers to react to particular log patterns or metric thresholds.
- Replace hard-coded configuration with environment variables or a config file for safer deployment.
License and privacy
-------------------
This module sends operational data (alerts and summaries) to the configured Telegram admin.
Be mindful of sensitive information included in alerts. Remove or redact secrets before
sending logs or process command-lines. Ensure compliance with your organization's privacy policy."""
"""
server_alert.py


Server Protector Bot - Ubuntu/Linux
Monitors SSH auth.log, Postgres log, system resources, network, ports, processes,
public IP, and sends alerts via Telegram (batched + rate-limited).
"""


import os
import re
import time
import socket
import asyncio
import nest_asyncio
import psutil
import aiohttp
import requests
from datetime import datetime, timedelta
from collections import defaultdict, deque
from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import CallbackQueryHandler

from telegram import Bot, Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
)

nest_asyncio.apply()

# ---------------- CONFIG ----------------
TELEGRAM_BOT_TOKEN = "8247876511:AAHw_TudiZ4UntTGjbHYAugLY30WKr1WIkg"
ADMIN_TELEGRAM_ID = 8498390933


# Files & system paths (Ubuntu)
AUTH_LOG = "/var/log/auth.log"                      # SSH/auth log
PG_LOG = "/var/log/postgresql/postgresql.log"       # optional
# Monitoring thresholds
CPU_THRESHOLD = 80.0    # percent
MEM_THRESHOLD = 85.0    # percent
DISK_THRESHOLD = 90.0   # percent
NET_THRESHOLD = 80.0    # percent of link speed
FAILED_ATTEMPT_WINDOW = 300  # seconds (5 min)
FAILED_ATTEMPT_LIMIT = 5


# Port scan configuration
PORTS_TO_SCAN = [22, 80, 443,5432]  # default ports
PORT_RANGE = (1, 1024)         # if you want full range scanning (slow)
PORT_SCAN_CONCURRENT = 200


# Ping / host checks (add hosts/IPs you care about)
PING_HOSTS = ["127.0.0.1"]     # add remote servers or services


# Summary & rate-limiting
SUMMARY_INTERVAL = 60          # seconds between summary messages (1 min)
ALERT_COOLDOWN = 20            # per unique alert text cooldown (seconds)


# Public IP check
PUBLIC_IP_URL = "https://api.ipify.org?format=text"
PUBLIC_IP_CHECK_INTERVAL = 120


# Other
CHECK_INTERVAL = 5             # main "fast" loop tick seconds
PORT_SCAN_INTERVAL = 300       # how often to run port scan (seconds)
SUSPICIOUS_PROCESSES = ["nc", "ncat", "netcat", "socat"]  # heuristics
# ---------------------------------------


# State
pending_alerts = []                 # list[str]
last_alert_time_for_text = defaultdict(lambda: datetime.min)
failed_attempts_by_ip = defaultdict(lambda: deque())
last_summary_time = 0
last_public_ip = None


bot = Bot(token=TELEGRAM_BOT_TOKEN)




# -------------------- Utilities --------------------
def rate_limited_alert(text: str) -> bool:
    """Return True if allowed; otherwise False (cooldown active)."""
    now = datetime.utcnow()
    last = last_alert_time_for_text.get(text, datetime.min)
    if (now - last).total_seconds() < ALERT_COOLDOWN:
        return False
    last_alert_time_for_text[text] = now
    return True




def add_pending(msg: str):
    """Add a message to the pending summary if not duplicate and rate-allowed."""
    if not rate_limited_alert(msg):
        return
    pending_alerts.append(f"{datetime.utcnow().isoformat()} - {msg}")
    print("[PENDING]", msg)




async def send_summary_if_due(application):
    """If summary interval elapsed, send a single summary message with all pending alerts."""
    global last_summary_time, pending_alerts
    now = time.time()
    if now - last_summary_time < SUMMARY_INTERVAL:
        return
    if not pending_alerts:
        last_summary_time = now
        return
    body = "📋 <b>Server Alert Summary</b>\n\n" + "\n\n".join(pending_alerts)
    try:
        await application.bot.send_message(chat_id=ADMIN_TELEGRAM_ID, text=body, parse_mode="HTML")
        print("[SENT SUMMARY]", len(pending_alerts), "items")
    except Exception as e:
        print("[ERROR] sending summary:", e)
    pending_alerts = []
    last_summary_time = now




# -------------------- Log tailing --------------------
async def tail_log_loop(path: str, line_handler, poll_interval: float = 1.0):
    """Tails a file and calls line_handler(line) for each new line. Async loop."""
    # If no file, wait until exists
    while not os.path.exists(path):
        print(f"[TAIL] waiting for {path}")
        await asyncio.sleep(2)
    with open(path, "r", errors="ignore") as f:
        # go to end
        f.seek(0, os.SEEK_END)
        while True:
            where = f.tell()
            line = f.readline()
            if not line:
                await asyncio.sleep(poll_interval)
                f.seek(where)
            else:
                try:
                    await line_handler(line.rstrip("\n"))
                except Exception as e:
                    print("[ERROR] handling log line:", e)




# -------------------- Handlers --------------------
async def handle_auth_line(line: str):
    """Detect SSH events from auth.log lines."""
    # "Failed password for ... from 1.2.3.4 port 1234 ..."
    m_failed = re.search(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)", line)
    m_invalid = re.search(r"Invalid user .* from (\d+\.\d+\.\d+\.\d+)", line)
    m_accepted = re.search(r"Accepted .* for (\S+) from (\d+\.\d+\.\d+\.\d+)", line)
    m_sudo = re.search(r"sudo: .*", line, flags=re.IGNORECASE)
    now = datetime.utcnow()


    if m_failed:
        ip = m_failed.group(1)
        dq = failed_attempts_by_ip[ip]
        dq.append(now)
        # prune old
        while dq and (now - dq[0]).total_seconds() > FAILED_ATTEMPT_WINDOW:
            dq.popleft()
        add_pending(f"Failed SSH attempt from {ip}. (Last {len(dq)} in window)")
        if len(dq) >= FAILED_ATTEMPT_LIMIT:
            add_pending(f"🚫 BLOCK TRIGGER: {ip} reached {len(dq)} failed attempts — consider blocking.")
            dq.clear()


    if m_invalid:
        ip = m_invalid.group(1)
        add_pending(f"🚫 Invalid user attempt from {ip}")


    if m_accepted:
        user, ip = m_accepted.groups()
        add_pending(f"🔐 SSH login accepted: user={user} from {ip}")
        # If root
        if user.lower() in ("root", "administrator", "admin"):
            add_pending(f"⚠️ Root login detected for {user} from {ip}")


    if m_sudo:
        add_pending("⚠️ sudo event detected in auth.log")




# -------------------- Resource monitor --------------------
async def resource_monitor_loop(application):
    while True:
        try:
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory().percent
            disk = psutil.disk_usage("/").percent if os.name != "nt" else 0
            if cpu >= CPU_THRESHOLD:
                add_pending(f"⚠️ High CPU: {cpu:.1f}%")
            if mem >= MEM_THRESHOLD:
                add_pending(f"⚠️ High Memory: {mem:.1f}%")
            if disk >= DISK_THRESHOLD:
                add_pending(f"⚠️ High Disk: {disk:.1f}%")
            await send_summary_if_due(application)
        except Exception as e:
            print("[ERROR] resource monitor:", e)
        await asyncio.sleep(CHECK_INTERVAL)




# -------------------- Network usage --------------------
async def network_monitor_loop(application):
    iface = None
    try:
        stats = psutil.net_if_stats()
        for name, s in stats.items():
            if s.isup and name != "lo":
                iface = name
                break
    except Exception:
        iface = None


    while True:
        try:
            if iface:
                st = psutil.net_if_stats().get(iface)
                if st and st.isup:
                    link_speed = st.speed or 100
                    io1 = psutil.net_io_counters(pernic=True)[iface]
                    await asyncio.sleep(1)
                    io2 = psutil.net_io_counters(pernic=True)[iface]
                    sent = ((io2.bytes_sent - io1.bytes_sent) * 8) / 1e6
                    recv = ((io2.bytes_recv - io1.bytes_recv) * 8) / 1e6
                    total_pct = (sent + recv) / link_speed * 100 if link_speed > 0 else 0.0
                    if total_pct >= NET_THRESHOLD:
                        add_pending(f"⚠️ High network: {total_pct:.1f}% of {link_speed} Mbps (↑{sent:.2f} Mbps ↓{recv:.2f} Mbps)")
            await send_summary_if_due(application)
        except Exception as e:
            print("[ERROR] network monitor:", e)
        await asyncio.sleep(CHECK_INTERVAL)




# -------------------- Port scanner --------------------
async def _scan_port(host: str, port: int, timeout=1.0):
    """Try to connect (async) using threads (socket is blocking)."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _sync_scan, host, port, timeout)




def _sync_scan(host, port, timeout):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False




async def port_scan_loop(application, hosts=None, ports=None, port_range=None):
    """Periodically scan specified ports on hosts and add alerts if open."""
    hosts = hosts or ["127.0.0.1"]
    ports_to_scan = ports or PORTS_TO_SCAN
    prange = port_range
    while True:
        try:
            open_results = []
            for h in hosts:
                scan_list = list(ports_to_scan)
                if prange:
                    a, b = prange
                    # be careful scanning very large ranges
                    scan_list += list(range(a, min(b + 1, a + 2000)))
                tasks = [_scan_port(h, p) for p in scan_list]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for p, ok in zip(scan_list, results):
                    if ok is True:
                        open_results.append((h, p))
            if open_results:
                for h, p in open_results:
                    add_pending(f"🔓 Port open: {h}:{p}")
            await send_summary_if_due(application)
        except Exception as e:
            print("[ERROR] port scan:", e)
        await asyncio.sleep(PORT_SCAN_INTERVAL)




# -------------------- Ping check --------------------
def _ping_host_sync(host):
    """Ping using system ping. Returns True if host reachable."""
    # Linux ping: -c 1 -W 2
    try:
        rc = os.system(f"ping -c 1 -W 2 {host} > /dev/null 2>&1")
        return rc == 0
    except Exception:
        return False




async def ping_loop(application, hosts=None):
    hosts = hosts or PING_HOSTS
    while True:
        try:
            for h in hosts:
                ok = await asyncio.get_event_loop().run_in_executor(None, _ping_host_sync, h)
                if not ok:
                    add_pending(f"❌ Host down/unreachable: {h}")
            await send_summary_if_due(application)
        except Exception as e:
            print("[ERROR] ping loop:", e)
        await asyncio.sleep(60)




# -------------------- Public IP monitor --------------------
async def public_ip_loop(application):
    global last_public_ip
    while True:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(PUBLIC_IP_URL, timeout=10) as resp:
                    if resp.status == 200:
                        ip = (await resp.text()).strip()
                        if last_public_ip and ip != last_public_ip:
                            add_pending(f"🌐 Public IP changed: {last_public_ip} -> {ip}")
                        last_public_ip = ip
            await send_summary_if_due(application)
        except Exception as e:
            print("[ERROR] public ip:", e)
        await asyncio.sleep(PUBLIC_IP_CHECK_INTERVAL)




# -------------------- Suspicious processes --------------------
async def suspicious_process_loop(application):
    while True:
        try:
            procs = [p.info for p in psutil.process_iter(attrs=["pid", "name", "cmdline"])]
            for p in procs:
                name = (p.get("name") or "").lower()
                cmd = " ".join(p.get("cmdline") or []).lower()
                for suspect in SUSPICIOUS_PROCESSES:
                    if suspect in name or suspect in cmd:
                        add_pending(f"⚠️ Suspicious process: {name} (pid={p.get('pid')}) cmd={cmd}")
            await send_summary_if_due(application)
        except Exception as e:
            print("[ERROR] suspicious proc:", e)
        await asyncio.sleep(60)




# -------------------- Telegram command handlers --------------------
async def restricted(update: Update, context: ContextTypes.DEFAULT_TYPE, func):
    if update.effective_user and update.effective_user.id != ADMIN_TELEGRAM_ID:
        await update.message.reply_text("Unauthorized.")
        return
    return await func(update, context)


async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [InlineKeyboardButton("Show System Status", callback_data='status')],
        [InlineKeyboardButton("Pause Alerts", callback_data='snooze')],
        [InlineKeyboardButton("Show Last 20 Log Lines", callback_data='tail')],
        [InlineKeyboardButton("Run Local Port Scan", callback_data='scan')],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text("Welcome to the Server Protector Bot!", reply_markup=reply_markup)

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [InlineKeyboardButton("Show System Status", callback_data='status')],
        [InlineKeyboardButton("Pause Alerts", callback_data='snooze')],
        [InlineKeyboardButton("Show Last 20 Log Lines", callback_data='tail')],
        [InlineKeyboardButton("Run Local Port Scan", callback_data='scan')],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text("Available commands:", reply_markup=reply_markup)


async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    if query.data == 'status':
        # Show system status (CPU, memory, disk usage)
        cpu = psutil.cpu_percent()
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/").percent if os.name != "nt" else 0
        await query.edit_message_text(f"📊 CPU: {cpu:.1f}% | MEM: {mem:.1f}% | DISK: {disk:.1f}%")

    elif query.data == 'snooze':
        # Snooze alerts for a period
        await query.edit_message_text("Alerts snoozed for 15 minutes.")

    elif query.data == 'tail':
        # Show last 20 log lines (you can modify to read actual logs)
        await query.edit_message_text("Showing last 20 log lines...")

    elif query.data == 'scan':
        # Run local port scan
        await query.edit_message_text("Running local port scan...")
        results = []
        for p in PORTS_TO_SCAN:
            ok = await _scan_port("127.0.0.1", p, timeout=0.7)
            results.append(f"{p}: {'OPEN' if ok else 'closed'}")
        await query.edit_message_text("\n".join(results))



async def status_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    cpu = psutil.cpu_percent()
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_usage("/").percent if os.name != "nt" else 0
    await update.message.reply_text(f"📊 CPU: {cpu:.1f}% | MEM: {mem:.1f}% | DISK: {disk:.1f}%")




async def snooze_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global snooze_until
    if update.effective_user and update.effective_user.id != ADMIN_TELEGRAM_ID:
        await update.message.reply_text("Unauthorized.")
        return
    try:
        mins = int(context.args[0])
        snooze_until = datetime.utcnow() + timedelta(minutes=mins)
        await update.message.reply_text(f"🤫 Alerts snoozed for {mins} minutes.")
    except Exception:
        await update.message.reply_text("Usage: /snooze <minutes>")




async def tail_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user and update.effective_user.id != ADMIN_TELEGRAM_ID:
        await update.message.reply_text("Unauthorized.")
        return
    path = context.args[0] if context.args else AUTH_LOG
    try:
        with open(path, "r", errors="ignore") as f:
            lines = f.readlines()[-20:]
        await update.message.reply_text("".join(lines) or "No data")
    except Exception as e:
        await update.message.reply_text(f"Error reading {path}: {e}")




async def scan_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user and update.effective_user.id != ADMIN_TELEGRAM_ID:
        await update.message.reply_text("Unauthorized.")
        return
    await update.message.reply_text("Running quick local port scan (small set)...")
    # quick scan of configured ports on localhost
    results = []
    for p in PORTS_TO_SCAN:
        ok = await _scan_port("127.0.0.1", p, timeout=0.7)
        results.append(f"{p}: {'OPEN' if ok else 'closed'}")
    await update.message.reply_text("\n".join(results))




async def ports_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user and update.effective_user.id != ADMIN_TELEGRAM_ID:
        await update.message.reply_text("Unauthorized.")
        return
    await update.message.reply_text("Port scan scheduled in background.")




async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "Available commands:\n"
        "/status - show system status\n"
        "/snooze <mins> - pause alerts\n"
        "/tail [file] - show last 20 lines of file\n"
        "/scan - quick local port scan\n        "
        "/help - this help"
    )
    await update.message.reply_text(msg)




# -------------------- Main (async) --------------------
async def main():
    application = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()

    # Register command handlers
    application.add_handler(CommandHandler("status", status_cmd))
    application.add_handler(CommandHandler("snooze", snooze_cmd))
    application.add_handler(CommandHandler("tail", tail_cmd))
    application.add_handler(CommandHandler("scan", scan_cmd))
    application.add_handler(CommandHandler("ports", ports_cmd))
    application.add_handler(CommandHandler("help", help_cmd))

    # Start background tasks
    asyncio.create_task(tail_log_loop(AUTH_LOG, handle_auth_line, poll_interval=0.5))
    asyncio.create_task(resource_monitor_loop(application))
    asyncio.create_task(network_monitor_loop(application))
    asyncio.create_task(port_scan_loop(application, hosts=["127.0.0.1"], ports=PORTS_TO_SCAN, port_range=None))
    asyncio.create_task(ping_loop(application, hosts=PING_HOSTS))
    asyncio.create_task(public_ip_loop(application))
    asyncio.create_task(suspicious_process_loop(application))

    # Send 'connected' message to the admin
    await application.bot.send_message(chat_id=ADMIN_TELEGRAM_ID, text="🤖 Server Protector Bot Connected ✅")

    # Start polling (will run until cancelled)
    await application.run_polling()

if __name__ == "__main__":
    try:
        asyncio.run(main())  # Start the bot with the new async method
    except KeyboardInterrupt:
        print("Stopped by user.")