#!/usr/env python3
"""
Outage monitor.

Checks websites, Minecraft servers and Discord bots, alerts a Discord webhook
when something goes down or recovers, and builds both a public status dashboard
(site/index.html) and an encrypted private dashboard (site/admin/index.html).
"""

import argparse
import asyncio
import base64
import hashlib
import json
import math
import os
import random
import secrets
import socket
import ssl
import struct
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import requests


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

def _env(name, default=""):
    value = os.environ.get(name, "").strip()
    return value if value else default


def _env_int(name, default):
    try:
        return int(_env(name, str(default)))
    except ValueError:
        return default


def _env_list(*names):
    for name in names:
        value = _env(name)
        if value:
            return [x.strip() for x in value.split(",") if x.strip()]
    return []


WEBHOOK_URL = _env("DISCORD_WEBHOOK_URL")
BOT_TOKEN = _env("MONITOR_BOT_TOKEN")
GUILD_ID = _env_int("GUILD_ID", 0)
TARGET_BOT_IDS = [int(x) for x in _env_list("BOT_IDS") if x.isdigit()]
WEBSITE_URLS = _env_list("WEBSITE_URLS", "WEBSITE_URL")
MC_SERVER_IPS = _env_list("MC_SERVER_IPS", "MC_SERVER_IP")
ALERT_ROLE_ID = _env("ALERT_ROLE_ID")

DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "")
DASHBOARD_TITLE = _env("DASHBOARD_TITLE", "Outages")
DASHBOARD_URL = _env("DASHBOARD_URL")

FAILURE_THRESHOLD = max(1, _env_int("FAILURE_THRESHOLD", 2))
RETRIES = max(0, _env_int("CHECK_RETRIES", 2))
RETRY_DELAY = 3
CERT_WARN_DAYS = _env_int("CERT_WARN_DAYS", 14)

STATE_FILE = Path(_env("STATE_FILE", "status.json"))
SITE_DIR = Path(_env("SITE_DIR", "site"))
TEMPLATE_FILE = Path(__file__).with_name("dashboard.html")

STATE_VERSION = 2
CHECK_INTERVAL = 300
RECENT_MAX = 288
HISTORY_DAYS = 90
INCIDENTS_MAX = 50
PBKDF2_ITERATIONS = 600_000

COLOR_DOWN = 0xED4245
COLOR_UP = 0x57F287
COLOR_WARN = 0xFEE75C


def log(level, message):
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{stamp} UTC] [{level}] {message}", flush=True)


# --------------------------------------------------------------------------- #
# Check results
# --------------------------------------------------------------------------- #

@dataclass
class Check:
    key: str
    name: str
    kind: str
    target: str
    ok: Optional[bool]
    detail: str
    latency_ms: Optional[int] = None
    info: str = ""
    mention: str = ""
    cert_days: Optional[int] = None


def format_duration(seconds):
    seconds = max(0, int(seconds))
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
    return " ".join(parts[:3])


# --------------------------------------------------------------------------- #
# Website check
# --------------------------------------------------------------------------- #

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


def _http_once(url):
    start = time.perf_counter()
    try:
        resp = requests.get(url, headers=BROWSER_HEADERS, timeout=15, allow_redirects=True, stream=True)
        latency = round((time.perf_counter() - start) * 1000)
        code = resp.status_code
        resp.close()
    except requests.exceptions.Timeout:
        return False, "Timed out after 15 s", None
    except requests.exceptions.SSLError:
        return False, "TLS certificate error", None
    except requests.exceptions.ConnectionError as e:
        return False, f"Connection failed ({type(e).__name__})", None
    except Exception as e:
        return False, f"Error ({type(e).__name__})", None

    if code < 400:
        return True, f"HTTP {code}", latency
    if code in (401, 403, 429):
        return True, f"HTTP {code} (bot protection answered)", latency
    return False, f"HTTP {code}", latency


def _cert_days_left(url):
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=8) as raw:
            with ctx.wrap_socket(raw, server_hostname=parsed.hostname) as tls:
                cert = tls.getpeercert()
        expires = ssl.cert_time_to_seconds(cert["notAfter"])
        return math.floor((expires - time.time()) / 86400)
    except Exception:
        return None


def check_website(key, name, url):
    ok, detail, latency = False, "No response", None
    for attempt in range(RETRIES + 1):
        ok, detail, latency = _http_once(url)
        if ok:
            break
        if attempt < RETRIES:
            time.sleep(RETRY_DELAY)

    cert_days = _cert_days_left(url) if ok else None
    info = ""
    if cert_days is not None:
        info = (
            f"Certificate expires in {cert_days} days"
            if cert_days >= 0
            else "Certificate has expired"
        )
    return Check(key, name, "website", url, ok, detail, latency, info, cert_days=cert_days)


# --------------------------------------------------------------------------- #
# Minecraft check (Server List Ping)
# --------------------------------------------------------------------------- #

def _pack_varint(val):
    out = bytearray()
    while True:
        byte = val & 0x7F
        val >>= 7
        out.append(byte | (0x80 if val > 0 else 0))
        if val == 0:
            break
    return bytes(out)


def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed early")
        buf += chunk
    return bytes(buf)


def _read_varint(sock):
    val = 0
    for i in range(5):
        byte = _recv_exact(sock, 1)[0]
        val |= (byte & 0x7F) << (7 * i)
        if not (byte & 0x80):
            return val
    raise ValueError("VarInt too big")


def resolve_mc_srv(address):
    if ":" in address:
        host, port_str = address.rsplit(":", 1)
        return host, int(port_str)
    try:
        import dns.resolver
        for rdata in dns.resolver.resolve(f"_minecraft._tcp.{address}", "SRV"):
            return str(rdata.target).rstrip("."), int(rdata.port)
    except Exception:
        pass
    return address, 25565


def _mc_ping_once(host, port):
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            sock.settimeout(10)
            host_bytes = host.encode("utf-8")
            handshake = (
                b"\x00"
                + _pack_varint(765)
                + _pack_varint(len(host_bytes))
                + host_bytes
                + struct.pack(">H", port)
                + b"\x01"
            )
            sock.sendall(_pack_varint(len(handshake)) + handshake)
            sock.sendall(b"\x01\x00")

            _read_varint(sock)
            if _read_varint(sock) != 0:
                raise ValueError("Invalid status packet")
            json_len = _read_varint(sock)
            if json_len > 1_000_000:
                raise ValueError("Status response too large")
            data = json.loads(_recv_exact(sock, json_len).decode("utf-8"))
            latency = round((time.perf_counter() - start) * 1000)
    except Exception as e:
        return None, None, f"No response ({type(e).__name__})"
    return data, latency, ""


def check_minecraft(key, name, address):
    clean = address.replace("https://", "").replace("http://", "").strip("/")
    host, port = resolve_mc_srv(clean)

    data, latency, error = None, None, ""
    for attempt in range(RETRIES + 1):
        data, latency, error = _mc_ping_once(host, port)
        if data is not None:
            break
        if attempt < RETRIES:
            time.sleep(RETRY_DELAY)

    target = clean if f"{host}:{port}" == clean else f"{clean} ({host}:{port})"
    if data is None:
        return Check(key, name, "minecraft", target, False, error)

    players = data.get("players", {})
    online, maximum = players.get("online", "?"), players.get("max", "?")
    version = (data.get("version") or {}).get("name", "")
    return Check(
        key, name, "minecraft", target, True,
        f"{online} of {maximum} players online", latency,
        f"Version {version}" if version else "",
    )


# --------------------------------------------------------------------------- #
# Discord bot presence check
# --------------------------------------------------------------------------- #

async def check_discord_bots():
    if not (BOT_TOKEN and TARGET_BOT_IDS and GUILD_ID):
        return []

    try:
        import discord
    except ImportError:
        log("ERROR", "discord.py is not installed, skipping bot checks.")
        return []

    def unknown(reason):
        return [
            Check(f"bot_{bot_id}", f"Bot {bot_id}", "bot", f"ID {bot_id}", None, reason,
                  mention=f"<@{bot_id}>")
            for bot_id in TARGET_BOT_IDS
        ]

    intents = discord.Intents.none()
    intents.guilds = True
    intents.members = True
    intents.presences = True
    client = discord.Client(intents=intents)
    results = []

    @client.event
    async def on_ready():
        try:
            guild = client.get_guild(GUILD_ID)
            if guild is None:
                log("WARNING", f"Monitor bot cannot access guild {GUILD_ID}")
                results.extend(unknown("Monitor bot cannot see the server"))
                return
            try:
                await guild.chunk()
            except Exception:
                pass
            await asyncio.sleep(2.0)

            for bot_id in TARGET_BOT_IDS:
                member = guild.get_member(bot_id)
                if member is None:
                    try:
                        member = await guild.fetch_member(bot_id)
                    except Exception:
                        member = None
                if member is None:
                    results.append(Check(
                        f"bot_{bot_id}", f"Bot {bot_id}", "bot", f"ID {bot_id}", False,
                        "Not a member of the server", mention=f"<@{bot_id}>"))
                    continue

                status = str(getattr(member, "status", "offline")).lower()
                online = status in ("online", "idle", "dnd") or bool(member.activities)
                results.append(Check(
                    f"bot_{bot_id}", member.display_name, "bot", f"ID {bot_id}", online,
                    f"Online ({status})" if online else "Offline",
                    mention=f"<@{bot_id}>"))
        except Exception as e:
            log("ERROR", f"Bot check failed: {e}")
        finally:
            await client.close()

    try:
        await asyncio.wait_for(client.start(BOT_TOKEN), timeout=40.0)
    except asyncio.TimeoutError:
        log("ERROR", "Discord bot check timed out.")
        try:
            await client.close()
        except Exception:
            pass
    except Exception as e:
        log("ERROR", f"Could not start Discord client: {type(e).__name__}: {e}")

    return results or unknown("Monitor could not reach Discord")


# --------------------------------------------------------------------------- #
# State
# --------------------------------------------------------------------------- #

def new_service():
    return {
        "name": "", "kind": "", "target": "",
        "down_since": None, "failures": 0, "alerted": False,
        "recent": [], "daily": {}, "cert_warned": 0,
    }


def empty_state():
    return {"version": STATE_VERSION, "services": {}, "incidents": []}


def load_state():
    if not STATE_FILE.exists():
        return empty_state()
    try:
        raw = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        log("WARNING", f"Could not read {STATE_FILE}: {e}")
        return empty_state()

    if isinstance(raw, dict) and raw.get("version") == STATE_VERSION:
        raw.setdefault("services", {})
        raw.setdefault("incidents", [])
        return raw

    state = empty_state()
    for key, value in (raw or {}).items():
        svc = new_service()
        if isinstance(value, (int, float)):
            svc.update(down_since=int(value), failures=FAILURE_THRESHOLD, alerted=True)
            state["incidents"].append(
                {"key": key, "name": key, "start": int(value), "end": None, "reason": "Outage in progress"})
        state["services"][key] = svc
    log("INFO", "Migrated old state file to the new format.")
    return state


def save_state(state):
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w", dir=STATE_FILE.parent, delete=False, encoding="utf-8", suffix=".tmp"
        ) as tf:
            json.dump(state, tf, separators=(",", ":"))
            temp_name = tf.name
        os.replace(temp_name, STATE_FILE)
    except Exception as e:
        log("ERROR", f"Failed to save state: {e}")


def utc_day(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d")


def record(svc, now, ok, latency):
    svc["recent"].append([now, 1 if ok else 0, latency])
    del svc["recent"][:-RECENT_MAX]
    day = svc["daily"].setdefault(utc_day(now), [0, 0])
    day[0] += 1 if ok else 0
    day[1] += 1
    cutoff = utc_day(now - HISTORY_DAYS * 86400)
    for stale in [d for d in svc["daily"] if d < cutoff]:
        del svc["daily"][stale]


def apply_results(state, checks, now):
    outages, recoveries, cert_warnings = [], [], []
    services = state["services"]

    for stale_key in [k for k in services if k not in {c.key for c in checks}]:
        del services[stale_key]

    # Handle workflow maintenance inputs / maintenance.json overrides
    maint_input = os.environ.get("MAINTENANCE_TARGETS", "").strip()
    maintenance_file = Path("maintenance.json")
    
    if maint_input:
        try:
            parsed_json = json.loads(maint_input)
            if parsed_json:
                if isinstance(parsed_json, dict) and parsed_json.get("clear"):
                    if maintenance_file.exists():
                        maintenance_file.unlink()
                else:
                    existing_maint = {}
                    if maintenance_file.exists():
                        try:
                            existing_maint = json.loads(maintenance_file.read_text(encoding="utf-8"))
                        except Exception:
                            pass
                    existing_maint.update(parsed_json)
                    maintenance_file.write_text(json.dumps(existing_maint), encoding="utf-8")
            else:
                if maintenance_file.exists():
                    maintenance_file.unlink()
        except json.JSONDecodeError:
            if maint_input.lower() == "false" or not maint_input:
                if maintenance_file.exists():
                    maintenance_file.unlink()
            else:
                maintenance_file.write_text(json.dumps({maint_input: "Under maintenance"}), encoding="utf-8")

    maint_data = {}
    if maintenance_file.exists():
        try:
            maint_data = json.loads(maintenance_file.read_text(encoding="utf-8"))
            if maint_data.get("clear"):
                maint_data = {}
        except Exception:
            pass

    for check in checks:
        svc = services.setdefault(check.key, new_service())
        svc.update(name=check.name, kind=check.kind, target=check.target)

        # Check if service is listed in maintenance overrides
        if check.key in maint_data:
            maint_reason = maint_data[check.key]
            if isinstance(maint_reason, bool):
                maint_reason = "Under maintenance"
            
            check.ok = True
            check.detail = f"Under maintenance: {maint_reason}"
            svc["last"] = {"ok": True, "detail": check.detail, "latency": None, "info": "Maintenance"}

            if svc["alerted"]:
                for inc in reversed(state["incidents"]):
                    if inc["key"] == check.key and inc["end"] is None:
                        inc["end"] = now
                        break
                recoveries.append((check, now - (svc["down_since"] or now), uptime_pct(svc, now, 1)))
            svc.update(down_since=None, failures=0, alerted=False)
            continue

        svc["last"] = {"ok": check.ok, "detail": check.detail, "latency": check.latency_ms, "info": check.info}

        if check.ok is None:
            continue

        record(svc, now, check.ok, check.latency_ms)

        if check.ok:
            if svc["alerted"]:
                for inc in reversed(state["incidents"]):
                    if inc["key"] == check.key and inc["end"] is None:
                        inc["end"] = now
                        break
                recoveries.append((check, now - (svc["down_since"] or now), uptime_pct(svc, now, 1)))
            svc.update(down_since=None, failures=0, alerted=False)

            if check.cert_days is not None and check.cert_days <= CERT_WARN_DAYS \
                    and now - svc.get("cert_warned", 0) > 3 * 86400:
                svc["cert_warned"] = now
                cert_warnings.append(check)
        else:
            svc["failures"] += 1
            if svc["down_since"] is None:
                svc["down_since"] = now
            if svc["failures"] >= FAILURE_THRESHOLD and not svc["alerted"]:
                svc["alerted"] = True
                state["incidents"].append(
                    {"key": check.key, "name": check.name, "start": svc["down_since"],
                     "end": None, "reason": check.detail})
                outages.append((check, svc["down_since"]))

    del state["incidents"][:-INCIDENTS_MAX]
    return outages, recoveries, cert_warnings


def uptime_pct(svc, now, days):
    if days <= 1:
        window = [p for p in svc["recent"] if p[0] >= now - 86400]
        up, total = sum(p[1] for p in window), len(window)
    else:
        up = total = 0
        for i in range(days):
            day = svc["daily"].get(utc_day(now - i * 86400))
            if day:
                up += day[0]
                total += day[1]
    if not total:
        return None
    pct = up * 100 / total
    if up < total:
        pct = min(pct, 99.99)
    return round(pct, 2)


def service_status(svc):
    last = svc.get("last") or {}
    if last.get("ok") is None:
        return "unknown"
    if last.get("info") == "Maintenance":
        return "degraded"
    if last["ok"]:
        return "up"
    return "down" if svc["alerted"] else "degraded"


# --------------------------------------------------------------------------- #
# Discord alerts
# --------------------------------------------------------------------------- #

def _trim(text, limit):
    return text if len(text) <= limit else text[: limit - 1] + "..."


def _discord_target(check):
    return f"Bot: {check.mention}" if check.kind == "bot" else f"`{check.target}`"


def post_webhook(embeds, ping=False, dry_run=False):
    if not embeds:
        return
    payload = {"username": "Outages", "embeds": embeds[:10]}
    if ping and ALERT_ROLE_ID:
        payload["content"] = f"<@&{ALERT_ROLE_ID}>"
        payload["allowed_mentions"] = {"roles": [ALERT_ROLE_ID]}
    else:
        payload["allowed_mentions"] = {"parse": []}

    if dry_run or not WEBHOOK_URL:
        log("INFO" if dry_run else "WARNING",
            "Dry run, alert not sent:" if dry_run else "DISCORD_WEBHOOK_URL is not set, alert not sent:")
        print(json.dumps(payload, indent=2))
        return

    for _ in range(3):
        try:
            resp = requests.post(WEBHOOK_URL, json=payload, timeout=10)
        except Exception as e:
            log("ERROR", f"Webhook request failed: {e}")
            return
        if resp.status_code == 429:
            try:
                wait = float(resp.json().get("retry_after", 1))
            except Exception:
                wait = 1.0
            time.sleep(min(wait, 10))
            continue
        if resp.status_code >= 400:
            log("ERROR", f"Webhook returned HTTP {resp.status_code}: {resp.text[:200]}")
        return


def _embed(title, description, color, fields, footer):
    embed = {
        "title": title,
        "description": description,
        "color": color,
        "fields": fields[:25],
        "footer": {"text": footer},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if DASHBOARD_URL:
        embed["url"] = DASHBOARD_URL
    return embed


def send_alerts(outages, recoveries, cert_warnings, dry_run):
    if outages:
        fields = [{
            "name": _trim(check.name, 256),
            "value": _trim(
                f"{_discord_target(check)}\nDown since <t:{since}:R>\n```diff\n- {check.detail}\n```", 1024),
            "inline": False,
        } for check, since in outages]
        post_webhook([_embed(
            "Service outage detected",
            "These services are down and need attention:",
            COLOR_DOWN, fields, "Alerts once per incident")], ping=True, dry_run=dry_run)

    if recoveries:
        fields = []
        for check, downtime, uptime in recoveries:
            uptime_text = f"\n24 hour uptime: {uptime}%" if uptime is not None else ""
            fields.append({
                "name": _trim(check.name, 256),
                "value": _trim(
                    f"{_discord_target(check)}\nTotal downtime: **{format_duration(downtime)}**"
                    f"{uptime_text}\n```diff\n+ {check.detail}\n```", 1024),
                "inline": False,
            })
        post_webhook([_embed(
            "Service recovered", "These services are back online:",
            COLOR_UP, fields, "Service restored")], dry_run=dry_run)

    if cert_warnings:
        fields = [{
            "name": _trim(check.name, 256),
            "value": f"`{check.target}`\nThe TLS certificate expires in **{check.cert_days}** days.",
            "inline": False,
        } for check in cert_warnings]
        post_webhook([_embed(
            "Certificate expiring soon", "Renew these certificates before they lapse:",
            COLOR_WARN, fields, "Certificate check")], dry_run=dry_run)


# --------------------------------------------------------------------------- #
# Dashboard
# --------------------------------------------------------------------------- #

def build_payload(state, now):
    services = []
    days = [utc_day(now - i * 86400) for i in range(HISTORY_DAYS - 1, -1, -1)]
    for key, svc in state["services"].items():
        last = svc.get("last") or {}
        services.append({
            "key": key,
            "name": svc["name"],
            "kind": svc["kind"],
            "target": svc["target"],
            "status": service_status(svc),
            "detail": last.get("detail", ""),
            "info": last.get("info", ""),
            "latency": last.get("latency"),
            "down_since": svc["down_since"],
            "uptime": {
                "24h": uptime_pct(svc, now, 1),
                "7d": uptime_pct(svc, now, 7),
                "30d": uptime_pct(svc, now, 30),
                "90d": uptime_pct(svc, now, HISTORY_DAYS),
            },
            "days": [svc["daily"].get(d) for d in days],
            "recent": [p for p in svc["recent"] if p[0] >= now - 86400],
        })

    incidents = [
        {"name": i["name"], "start": i["start"], "end": i["end"], "reason": i["reason"]}
        for i in reversed(state["incidents"][-25:])
    ]
    return {
        "title": DASHBOARD_TITLE,
        "generated": now,
        "interval": CHECK_INTERVAL,
        "threshold": FAILURE_THRESHOLD,
        "days_end": days[-1],
        "services": services,
        "incidents": incidents,
    }


def _b64(data):
    return base64.b64encode(data).decode("ascii")


def encrypt_payload(payload, password):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    salt, iv = secrets.token_bytes(16), secrets.token_bytes(12)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=32)
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return {
        "mode": "encrypted",
        "iter": PBKDF2_ITERATIONS,
        "salt": _b64(salt),
        "iv": _b64(iv),
        "ct": _b64(AESGCM(key).encrypt(iv, plaintext, None)),
    }


def _render_html(payload, password, output_path):
    if not TEMPLATE_FILE.exists():
        raise SystemExit(f"Dashboard template missing: {TEMPLATE_FILE}")

    if password:
        try:
            blob = encrypt_payload(payload, password)
        except ImportError:
            raise SystemExit("The 'cryptography' package is required to encrypt the dashboard.")
    else:
        blob = {"mode": "plain", "payload": payload}

    data = json.dumps(blob, separators=(",", ":")).replace("</", "<\\/")
    html = TEMPLATE_FILE.read_text(encoding="utf-8").replace("__DASHBOARD_DATA__", data)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    log("INFO", f"Wrote {output_path} ({'encrypted' if password else 'public'}).")


def write_dashboards(payload, password):
    SITE_DIR.mkdir(parents=True, exist_ok=True)
    (SITE_DIR / ".nojekyll").write_text("", encoding="utf-8")

    # 1. Public dashboard at root (site/index.html)
    _render_html(payload, "", SITE_DIR / "index.html")

    # 2. Private encrypted dashboard at admin folder (site/admin/index.html)
    if password:
        _render_html(payload, password, SITE_DIR / "admin" / "index.html")


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

async def collect_checks():
    jobs = []
    for idx, url in enumerate(WEBSITE_URLS):
        key = f"website_{idx}" if len(WEBSITE_URLS) > 1 else "website"
        name = (urlparse(url).hostname or url) if len(WEBSITE_URLS) > 1 else "Website"
        jobs.append((check_website, key, name, url))
    for idx, address in enumerate(MC_SERVER_IPS):
        key = f"minecraft_{idx}" if len(MC_SERVER_IPS) > 1 else "minecraft"
        name = address if len(MC_SERVER_IPS) > 1 else "Minecraft server"
        jobs.append((check_minecraft, key, name, address))

    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [loop.run_in_executor(pool, fn, key, name, target) for fn, key, name, target in jobs]
        *simple, bots = await asyncio.gather(*futures, check_discord_bots())
    return list(simple) + list(bots)


async def main(args):
    now = int(time.time())

    state = load_state()
    checks = await collect_checks()
    for c in checks:
        verdict = {True: "up", False: "DOWN", None: "unknown"}[c.ok]
        log("INFO", f"{c.name}: {verdict} ({c.detail})")

    outages, recoveries, cert_warnings = apply_result_tuple = apply_results(state, checks, now)
    send_alerts(outages, recoveries, cert_warnings, args.dry_run)

    save_state(state)
    write_dashboards(build_payload(state, now), DASHBOARD_PASSWORD)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="print alerts instead of sending them")
    asyncio.run(main(parser.parse_args()))
