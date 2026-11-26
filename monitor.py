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

# Support single or multiple comma-separated websites and Minecraft servers
WEBSITE_URLS = [x.strip() for x in os.environ.get("WEBSITE_URLS", os.environ.get("WEBSITE_URL", "")).split(",") if x.strip()]
MC_SERVER_IPS = [x.strip() for x in os.environ.get("MC_SERVER_IPS", os.environ.get("MC_SERVER_IP", "")).split(",") if x.strip()]

ALERT_ROLE_ID = os.environ.get("ALERT_ROLE_ID", "").strip()
STATE_FILE = "status.json"


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
                for bot_id in TARGET_BOT_IDS:
                    try:
                        member = await guild.fetch_member(bot_id)
                        
                        # Check if member is a bot or user and evaluate their general online presence
                        # If a bot is connected to gateway, member.status won't be discord.Status.offline
                        is_online = member.status != discord.Status.offline and member.status != discord.Status.invisible
                        
                        # Alternative fallback: if member.raw_status exists or bot is active in voice/presence
                        if str(member.status) in ["online", "idle", "dnd"]:
                            is_online = True
                        else:
                            # If status comes back as offline/mobile/desktop checks
                            is_online = member.status != discord.Status.offline

                        status_label = f"Online ({str(member.status).upper()})" if is_online else "Status: OFFLINE"
                        
                        results[f"bot_{bot_id}"] = (
                            f"🤖 {member.display_name}",
                            is_online,
                            status_label,
                            f"Mention: <@{bot_id}>",
                        )
                    except discord.NotFound:
                        results[f"bot_{bot_id}"] = (
                            f"🤖 Bot ({bot_id})",
                            False,
                            "Missing from Discord server",
                            f"Mention: <@{bot_id}>",
                        )
                    except Exception as ex:
                        log("ERROR", f"Failed fetching member {bot_id}: {ex}")
                        results[f"bot_{bot_id}"] = (
                            f"🤖 Bot ({bot_id})",
                            False,
                            f"Error fetching member ({type(ex).__name__})",
                            f"Mention: <@{bot_id}>",
                        )
        except Exception as e:
            log("ERROR", f"Exception during bot check execution: {e}")
        finally:
            await client.close()

    try:
        await asyncio.wait_for(client.start(BOT_TOKEN), timeout=30.0)
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
    
    # Discord hard limit: max 25 fields per embed. Chunk fields if necessary.
    for embed in embeds:
        fields = embed.get("fields", [])
        if len(fields) > 25:
            log("INFO", "Chunking embed fields due to Discord's 25-field limit.")
            chunked_fields = [fields[i:i + 25] for i in range(0, len(fields), 25)]
            for idx, chunk in enumerate(chunked_fields):
                chunk_embed = embed.copy()
                chunk_embed["fields"] = chunk
                if idx > 0:
                    chunk_embed.pop("title", None) # Remove title on subsequent chunks for neatness
                
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


async def main():
    now = int(time.time())
    prev_state = load_state()
    new_state = {}
    checks = {}

    # Check all configured websites
    for idx, url in enumerate(WEBSITE_URLS):
        key = f"website_{idx}" if len(WEBSITE_URLS) > 1 else "website"
        ok, status_text, extra = check_website(url)
        log("INFO", f"Website check ({url}): {ok} -> {status_text}")
        checks[key] = ("🌐 Website", ok, status_text, extra)

    # Check all configured Minecraft servers
    for idx, ip in enumerate(MC_SERVER_IPS):
        key = f"minecraft_{idx}" if len(MC_SERVER_IPS) > 1 else "minecraft"
        ok, status_text, extra = check_minecraft(ip)
        log("INFO", f"Minecraft check ({ip}): {ok} -> {status_text}")
        checks[key] = ("⛏️ Minecraft Server", ok, status_text, extra)

    # Check Discord bots
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


if __name__ == "__main__":
    asyncio.run(main())
