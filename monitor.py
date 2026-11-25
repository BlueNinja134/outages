import os
import json
import time
import socket
import struct
import urllib.request
import asyncio
from datetime import datetime, timezone
import discord

WEBHOOK_URL = os.environ["DISCORD_WEBHOOK_URL"]
BOT_TOKEN = os.environ["MONITOR_BOT_TOKEN"]
GUILD_ID = int(os.environ["GUILD_ID"])
TARGET_BOT_IDS = [int(x.strip()) for x in os.environ["BOT_IDS"].split(",") if x.strip()]
WEBSITE_URL = os.environ.get("WEBSITE_URL", "").strip()
MC_SERVER_IP = os.environ.get("MC_SERVER_IP", "").strip()
ALERT_ROLE_ID = os.environ.get("ALERT_ROLE_ID", "").strip()

STATE_FILE = "status.json"


def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


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
    start = time.perf_counter()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "StatusMonitor/2.0"})
        with urllib.request.urlopen(req, timeout=10) as response:
            latency = round((time.perf_counter() - start) * 1000)
            if response.status >= 400:
                return False, f"HTTP Error {response.status}", f"Target: `{url}`"
            return True, f"Online ({latency}ms • HTTP {response.status})", f"Target: `{url}`"
    except Exception as e:
        return False, f"Unreachable ({type(e).__name__})", f"Target: `{url}`"


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


def check_minecraft(address):
    host, port_str = (address.split(":") + ["25565"])[:2]
    port = int(port_str)
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            sock.settimeout(10)
            # Send Minecraft Handshake + Status Request (Server List Ping)
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

            _ = _unpack_varint(sock)  # Packet length
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
            return True, f"Online ({latency}ms • {online}/{maximum} players)", f"Server: `{address}`"
    except Exception:
        return False, "Offline / Server Not Responding", f"Server: `{address}`"


async def check_discord_bots():
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
                for bot_id in TARGET_BOT_IDS:
                    results[f"bot_{bot_id}"] = (
                        f"🤖 Discord Bot ({bot_id})",
                        False,
                        "Monitor bot cannot access guild",
                        f"Mention: <@{bot_id}>",
                    )
            else:
                for bot_id in TARGET_BOT_IDS:
                    member = guild.get_member(bot_id)
                    if not member:
                        results[f"bot_{bot_id}"] = (
                            f"🤖 Bot ({bot_id})",
                            False,
                            "Missing from Discord server",
                            f"Mention: <@{bot_id}>",
                        )
                    elif member.status == discord.Status.offline:
                        results[f"bot_{bot_id}"] = (
                            f"🤖 {member.display_name}",
                            False,
                            "Status: OFFLINE",
                            f"Mention: <@{bot_id}>",
                        )
                    else:
                        results[f"bot_{bot_id}"] = (
                            f"🤖 {member.display_name}",
                            True,
                            f"Online ({str(member.status).upper()})",
                            f"Mention: <@{bot_id}>",
                        )
        finally:
            await client.close()

    await client.start(BOT_TOKEN)
    return results


def post_webhook(content, embeds):
    payload = {
        "username": "Outages",
        "embeds": embeds,
    }
    if content:
        payload["content"] = content
        if ALERT_ROLE_ID:
            payload["allowed_mentions"] = {"roles": [ALERT_ROLE_ID]}

    req = urllib.request.Request(
        WEBHOOK_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "StatusMonitor/2.0"},
        method="POST",
    )
    urllib.request.urlopen(req, timeout=10)


async def main():
    now = int(time.time())
    prev_state = load_state()
    new_state = {}

    # Format: key -> (Display Name, is_online, status_text, extra_info)
    checks = {}

    if WEBSITE_URL:
        ok, status_text, extra = check_website(WEBSITE_URL)
        checks["website"] = ("🌐 Website", ok, status_text, extra)

    if MC_SERVER_IP:
        ok, status_text, extra = check_minecraft(MC_SERVER_IP)
        checks["minecraft"] = ("⛏️ Minecraft Server", ok, status_text, extra)

    bot_results = await check_discord_bots()
    checks.update(bot_results)

    new_outages = []
    recoveries = []

    for key, (name, is_online, status_text, extra) in checks.items():
        was_down_since = prev_state.get(key)

        if not is_online:
            if was_down_since is None:
                # Just went offline!
                new_state[key] = now
                new_outages.append((name, status_text, extra, now))
            else:
                # Still offline (keep original timestamp, don't spam)
                new_state[key] = was_down_since
        else:
            new_state[key] = None
            if was_down_since is not None:
                # Just came back online!
                downtime = format_duration(now - was_down_since)
                recoveries.append((name, status_text, extra, downtime))

    # 1. Send Red Alert + Role Ping ONLY for newly detected outages
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

    # 2. Send Green Recovery Embed (no role ping spam) when services come back
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
            "footer": {"text": "Outages • Incident Resolved"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        post_webhook("", [recovery_embed])

    if not new_outages and not recoveries:
        print("No status changes detected.")

    save_state(new_state)


if __name__ == "__main__":
    asyncio.run(main())
