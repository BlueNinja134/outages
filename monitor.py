import os
import json
import time
import socket
import struct
import asyncio
import tempfile
from datetime import datetime, timezone
import requests
import dns.resolver
import discord

WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "")
BOT_TOKEN = os.environ.get("MONITOR_BOT_TOKEN", "")
GUILD_ID = int(os.environ.get("GUILD_ID", "0"))
TARGET_BOT_IDS = [int(x.strip()) for x in os.environ.get("BOT_IDS", "").split(",") if x.strip()]

WEBSITE_URLS = [x.strip() for x in os.environ.get("WEBSITE_URLS", os.environ.get("WEBSITE_URL", "")).split(",") if x.strip()]
MC_SERVER_IPS = [x.strip() for x in os.environ.get("MC_SERVER_IPS", os.environ.get("MC_SERVER_IP", "")).split(",") if x.strip()]

ALERT_ROLE_ID = os.environ.get("ALERT_ROLE_ID", "").strip()
STATE_FILE = "status.json"
DASHBOARD_FILE = "index.html"


def log(level, message):
    print(f"[{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC] [{level}] {message}")


def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            log("WARNING", f"Failed to load state file: {e}")
            return {}
    return {}


def save_state(state):
    try:
        dir_name = os.path.dirname(STATE_FILE) or "."
        with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False, encoding="utf-8") as tf:
            json.dump(state, tf, indent=2)
            temp_name = tf.name
        os.replace(temp_name, STATE_FILE)
    except Exception as e:
        log("ERROR", f"Failed to save state file: {e}")


def format_duration(seconds):
    seconds = int(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if secs or not parts:
        parts.append(f"{secs}s")
    return " ".join(parts)


def check_website(url):
    if not url:
        return False, "No URL specified", ""
    start = time.perf_counter()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    try:
        resp = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
        latency = round((time.perf_counter() - start) * 1000)

        if resp.status_code < 400:
            return True, f"Online ({latency}ms • HTTP {resp.status_code})", f"Target: `{url}`"

        if resp.status_code in (401, 403, 429):
            return True, f"Online ({latency}ms • Cloudflare Protected {resp.status_code})", f"Target: `{url}`"

        return False, f"Server Error (HTTP {resp.status_code})", f"Target: `{url}`"

    except requests.exceptions.Timeout:
        return False, "Connection Timed Out (>15s)", f"Target: `{url}`"
    except requests.exceptions.ConnectionError as e:
        return False, f"Connection Failed ({type(e).__name__})", f"Target: `{url}`"
    except Exception as e:
        return False, f"Error ({type(e).__name__}: {e})", f"Target: `{url}`"


def _pack_varint(val):
    out = bytearray()
    while True:
        byte = val & 0x7F
        val >>= 7
        out.append(byte | (0x80 if val > 0 else 0))
        if val == 0:
            break
    return bytes(out)


def _unpack_varint(sock):
    val = 0
    for i in range(5):
        raw = sock.recv(1)
        if not raw:
            raise ConnectionError("Unexpected EOF")
        byte = raw[0]
        val |= (byte & 0x7F) << (7 * i)
        if not (byte & 0x80):
            return val
    raise ValueError("VarInt too big")


def resolve_mc_srv(address):
    if ":" in address:
        host, port_str = address.split(":", 1)
        return host, int(port_str)
    try:
        answers = dns.resolver.resolve(f"_minecraft._tcp.{address}", "SRV")
        for rdata in answers:
            return str(rdata.target).rstrip("."), int(rdata.port)
    except Exception:
        pass
    return address, 25565


def check_minecraft(address):
    if not address:
        return False, "No address specified", ""
    clean_addr = address.replace("https://", "").replace("http://", "").strip("/")
    host, port = resolve_mc_srv(clean_addr)
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            sock.settimeout(10)
            host_bytes = host.encode("utf-8")
            handshake_data = (
                b"\x00"
                + _pack_varint(765)
                + _pack_varint(len(host_bytes))
                + host_bytes
                + struct.pack(">H", port)
                + b"\x01"
            )
            sock.sendall(_pack_varint(len(handshake_data)) + handshake_data)
            sock.sendall(b"\x01\x00")

            _ = _unpack_varint(sock)
            packet_id = _unpack_varint(sock)
            if packet_id != 0:
                raise ValueError("Invalid status packet")

            json_len = _unpack_varint(sock)
            raw_json = b""
            while len(raw_json) < json_len:
                chunk = sock.recv(json_len - len(raw_json))
                if not chunk:
                    break
                raw_json += chunk

            latency = round((time.perf_counter() - start) * 1000)
            data = json.loads(raw_json.decode("utf-8"))
            players = data.get("players", {})
            online = players.get("online", "?")
            maximum = players.get("max", "?")
            return True, f"Online ({latency}ms • {online}/{maximum} players)", f"Server: `{clean_addr}`"
    except Exception as e:
        return False, f"Offline ({type(e).__name__})", f"Server: `{clean_addr}` (`{host}:{port}`)"


async def check_discord_bots():
    if not BOT_TOKEN or not TARGET_BOT_IDS or not GUILD_ID:
        return {}

    intents = discord.Intents.default()
    intents.presences = True
    intents.members = True
    
    client = discord.Client(intents=intents)
    results = {}

    @client.event
    async def on_ready():
        try:
            guild = client.get_guild(GUILD_ID)
            if not guild:
                log("WARNING", f"Monitor bot cannot access guild ID {GUILD_ID}")
                for bot_id in TARGET_BOT_IDS:
                    results[f"bot_{bot_id}"] = (
                        f"🤖 Discord Bot ({bot_id})",
                        False,
                        "Monitor bot cannot access guild",
                        f"Mention: <@{bot_id}>",
                    )
            else:
                # Chunk guild and wait for gateway presence cache to populate
                try:
                    await guild.chunk()
                except Exception:
                    pass
                await asyncio.sleep(3.0)

                for bot_id in TARGET_BOT_IDS:
                    member = guild.get_member(bot_id)
                    if not member:
                        try:
                            member = await guild.fetch_member(bot_id)
                        except Exception:
                            pass

                    if not member:
                        results[f"bot_{bot_id}"] = (
                            f"🤖 Bot ({bot_id})",
                            False,
                            "Missing from Discord server",
                            f"Mention: <@{bot_id}>",
                        )
                        continue

                    status_str = str(getattr(member, "status", "offline")).lower()
                    # Consider online, idle, dnd, or any active presence as online
                    is_online = status_str in ["online", "idle", "dnd"] or bool(member.activities)

                    if is_online:
                        status_label = f"Online ({status_str.upper()})"
                        if member.activities:
                            activity_names = [act.name for act in member.activities]
                            status_label = f"Online ({', '.join(activity_names)})"
                    else:
                        status_label = "Status: OFFLINE"

                    results[f"bot_{bot_id}"] = (
                        f"🤖 {member.display_name}",
                        is_online,
                        status_label,
                        f"Mention: <@{bot_id}>",
                    )
        except Exception as e:
            log("ERROR", f"Exception during bot check execution: {e}")
        finally:
            await client.close()

    try:
        await asyncio.wait_for(client.start(BOT_TOKEN), timeout=35.0)
    except asyncio.TimeoutError:
        log("ERROR", "Discord bot check timed out.")
        try:
            await client.close()
        except:
            pass
        for bot_id in TARGET_BOT_IDS:
            if f"bot_{bot_id}" not in results:
                results[f"bot_{bot_id}"] = (
                    f"🤖 Discord Bot ({bot_id})",
                    False,
                    "Client connection timed out",
                    f"Mention: <@{bot_id}>",
                )
    except Exception as e:
        log("ERROR", f"Failed to start Discord client: {e}")

    return results


def post_webhook(content, embeds):
    if not WEBHOOK_URL:
        log("WARNING", "WEBHOOK_URL is not set. Skipping notification.")
        return
    
    for embed in embeds:
        fields = embed.get("fields", [])
        if len(fields) > 25:
            chunked_fields = [fields[i:i + 25] for i in range(0, len(fields), 25)]
            for idx, chunk in enumerate(chunked_fields):
                chunk_embed = embed.copy()
                chunk_embed["fields"] = chunk
                if idx > 0:
                    chunk_embed.pop("title", None)
                
                payload = {"username": "Outages", "embeds": [chunk_embed]}
                if content and idx == 0:
                    payload["content"] = content
                    if ALERT_ROLE_ID:
                        payload["allowed_mentions"] = {"roles": [ALERT_ROLE_ID]}
                
                try:
                    requests.post(WEBHOOK_URL, json=payload, timeout=10)
                except Exception as e:
                    log("ERROR", f"Failed to send webhook chunk: {e}")
            return

    payload = {
        "username": "Outages",
        "embeds": embeds,
    }
    if content:
        payload["content"] = content
        if ALERT_ROLE_ID:
            payload["allowed_mentions"] = {"roles": [ALERT_ROLE_ID]}

    try:
        requests.post(WEBHOOK_URL, json=payload, timeout=10)
    except Exception as e:
        log("ERROR", f"Failed to send webhook alert: {e}")


def generate_dashboard(checks, state):
    """Generates a secure, password-protected status web dashboard (index.html)"""
    items_html = ""
    all_operational = True

    for key, (name, is_online, status_text, extra) in checks.items():
        if not is_online:
            all_operational = False
            badge = '<span class="badge offline">Offline</span>'
            card_class = "card offline"
        else:
            badge = '<span class="badge online">Operational</span>'
            card_class = "card online"

        down_since = state.get(key)
        downtime_info = ""
        if down_since:
            downtime_duration = format_duration(time.time() - down_since)
            downtime_info = f'<div class="downtime">Down for: <strong>{downtime_duration}</strong></div>'

        items_html += f"""
        <div class="{card_class}">
            <div class="card-header">
                <h3>{name}</h3>
                {badge}
            </div>
            <div class="card-body">
                <p class="status-text">{status_text}</p>
                <p class="extra-info">{extra}</p>
                {downtime_info}
            </div>
        </div>
        """

    overall_banner = """
    <div class="banner operational">
        <h2>🟢 All Systems Operational</h2>
        <p>Every monitored service is currently online and running smoothly.</p>
    </div>
    """ if all_operational else """
    <div class="banner incident">
        <h2>🚨 Active Incident Detected</h2>
        <p>One or more services are currently experiencing outages.</p>
    </div>
    """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>System Status Dashboard</title>
    <style>
        :root {{
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --text-color: #c9d1d9;
            --border-color: #30363d;
            --online-color: #238636;
            --offline-color: #da3633;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 20px;
            display: flex;
            justify-content: center;
        }}
        .container {{
            width: 100%;
            max-width: 800px;
        }}
        #login-overlay {{
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(13, 17, 23, 0.95);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 1000;
        }}
        .login-box {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            padding: 30px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 8px 24px rgba(0,0,0,0.5);
        }}
        .login-box input {{
            padding: 10px;
            margin: 10px 0;
            background: #0d1117;
            border: 1px solid var(--border-color);
            color: white;
            border-radius: 4px;
            width: 80%;
        }}
        .login-box button {{
            padding: 10px 20px;
            background: var(--online-color);
            border: none;
            color: white;
            border-radius: 4px;
            cursor: pointer;
            font-weight: bold;
        }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 20px;
        }}
        .banner {{
            padding: 15px 20px;
            border-radius: 6px;
            margin-bottom: 20px;
            border: 1px solid var(--border-color);
        }}
        .banner.operational {{ background: rgba(35, 134, 54, 0.15); border-color: var(--online-color); }}
        .banner.incident {{ background: rgba(218, 54, 51, 0.15); border-color: var(--offline-color); }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            margin-bottom: 15px;
            padding: 20px;
        }}
        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .badge {{
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            color: white;
        }}
        .badge.online {{ background-color: var(--online-color); }}
        .badge.offline {{ background-color: var(--offline-color); }}
        .card-body {{ margin-top: 10px; font-size: 14px; }}
        .extra-info {{ color: #8b949e; font-family: monospace; }}
        .downtime {{ color: var(--offline-color); margin-top: 5px; }}
        footer {{ text-align: center; margin-top: 40px; color: #8b949e; font-size: 12px; }}
    </style>
</head>
<body>
    <!-- Simple Password Login Overlay -->
    <div id="login-overlay">
        <div class="login-box">
            <h2>🔒 Admin Login</h2>
            <p>Enter password to view status dashboard</p>
            <input type="password" id="password-input" placeholder="Password"><br>
            <button onclick="checkPassword()">Login</button>
            <p id="error-msg" style="color: var(--offline-color); font-size: 12px; display: none; margin-top: 10px;">Incorrect password</p>
        </div>
    </div>

    <div class="container">
        <header>
            <h1>🛡️ System Watchdog</h1>
            <span>Last Updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC</span>
        </header>

        {overall_banner}

        <div class="services-list">
            {items_html}
        </div>

        <footer>
            Powered by System Watchdog & GitHub Pages
        </footer>
    </div>

    <script>
        // Default password is 'admin123' - you can change it here!
        const CORRECT_HASH = "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a3"; // SHA-256 for 'admin123'
        
        async function sha256(message) {{
            const msgBuffer = new TextEncoder().encode(message);
            const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        }}

        async function checkPassword() {{
            const pwd = document.getElementById('password-input').value;
            const hash = await sha256(pwd);
            if (hash === CORRECT_HASH) {{
                document.getElementById('login-overlay').style.display = 'none';
                localStorage.setItem('auth_success', 'true');
            }} else {{
                document.getElementById('error-msg').style.display = 'block';
            }}
        }}

        // Remember login session
        if (localStorage.getItem('auth_success') === 'true') {{
            document.getElementById('login-overlay').style.display = 'none';
        }}
    </script>
</body>
</html>
"""
    try:
        with open(DASHBOARD_FILE, "w", encoding="utf-8") as f:
            f.write(html_content)
        log("INFO", "Successfully generated index.html status dashboard.")
    except Exception as e:
        log("ERROR", f"Failed to generate dashboard HTML: {e}")


async def main():
    now = int(time.time())
    prev_state = load_state()
    new_state = {}
    checks = {}

    for idx, url in enumerate(WEBSITE_URLS):
        key = f"website_{idx}" if len(WEBSITE_URLS) > 1 else "website"
        ok, status_text, extra = check_website(url)
        log("INFO", f"Website check ({url}): {ok} -> {status_text}")
        checks[key] = ("🌐 Website", ok, status_text, extra)

    for idx, ip in enumerate(MC_SERVER_IPS):
        key = f"minecraft_{idx}" if len(MC_SERVER_IPS) > 1 else "minecraft"
        ok, status_text, extra = check_minecraft(ip)
        log("INFO", f"Minecraft check ({ip}): {ok} -> {status_text}")
        checks[key] = ("⛏️ Minecraft Server", ok, status_text, extra)

    bot_results = await check_discord_bots()
    for k, v in bot_results.items():
        log("INFO", f"Bot check ({k}): {v[1]} -> {v[2]}")
    checks.update(bot_results)

    new_outages = []
    recoveries = []

    for key, (name, is_online, status_text, extra) in checks.items():
        was_down_since = prev_state.get(key)

        if not is_online:
            if was_down_since is None:
                new_state[key] = now
                new_outages.append((name, status_text, extra, now))
            else:
                new_state[key] = was_down_since
        else:
            new_state[key] = None
            if was_down_since is not None:
                downtime = format_duration(now - was_down_since)
                recoveries.append((name, status_text, extra, downtime))

    if new_outages:
        fields = []
        for name, status_text, extra, down_ts in new_outages:
            fields.append({
                "name": name,
                "value": f"{extra} • Detected <t:{down_ts}:R>\n```diff\n- {status_text}\n```",
                "inline": False,
            })

        outage_embed = {
            "title": "🚨 Service Outage Detected",
            "description": "The following service(s) just went **OFFLINE** and require attention:",
            "color": 15548997,
            "fields": fields,
            "footer": {"text": "Outages • Alerting once per incident"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        ping_text = f"<@&{ALERT_ROLE_ID}>" if ALERT_ROLE_ID else ""
        post_webhook(ping_text, [outage_embed])

    if recoveries:
        fields = []
        for name, status_text, extra, downtime in recoveries:
            fields.append({
                "name": name,
                "value": f"{extra} • Total Downtime: **{downtime}**\n```diff\n+ {status_text}\n```",
                "inline": False,
            })

        recovery_embed = {
            "title": "✅ Service Recovered",
            "description": "The following service(s) are back **ONLINE**:",
            "color": 5763719,
            "fields": fields,
            "footer": {"text": "Outages • Service Restored"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        post_webhook("", [recovery_embed])

    save_state(new_state)
    generate_dashboard(checks, new_state)


if __name__ == "__main__":
    asyncio.run(main())
