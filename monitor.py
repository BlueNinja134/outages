import os
import json
import socket
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


def check_website(url):
    if not url:
        return None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "StatusMonitor/1.0"})
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status >= 400:
                return {
                    "name": "🌐 Website Down",
                    "value": f"Target: `{url}`\n```HTTP Status {response.status}```",
                    "inline": False,
                }
        return None
    except Exception as e:
        return {
            "name": "🌐 Website Unreachable",
            "value": f"Target: `{url}`\n```{str(e)}```",
            "inline": False,
        }


def check_minecraft(address):
    if not address:
        return None
    host, port = (address.split(":") + ["25565"])[:2]
    try:
        with socket.create_connection((host, int(port)), timeout=10):
            return None
    except Exception:
        return {
            "name": "⛏️ Minecraft Server Offline",
            "value": f"Server: `{address}`\n```Connection timed out or refused```",
            "inline": False,
        }


async def check_discord_bots():
    intents = discord.Intents.default()
    intents.presences = True
    intents.members = True
    client = discord.Client(intents=intents)
    issues = []

    @client.event
    async def on_ready():
        try:
            guild = client.get_guild(GUILD_ID)
            if not guild:
                issues.append({
                    "name": "⚠️ Monitor Error",
                    "value": "```Monitor bot cannot find the Discord server (check GUILD_ID).```",
                    "inline": False,
                })
            else:
                for bot_id in TARGET_BOT_IDS:
                    member = guild.get_member(bot_id)
                    if not member:
                        issues.append({
                            "name": "🤖 Bot Missing",
                            "value": f"Bot: <@{bot_id}>\n```ID {bot_id} is not in the server```",
                            "inline": False,
                        })
                    elif member.status == discord.Status.offline:
                        issues.append({
                            "name": f"🤖 {member.display_name} Offline",
                            "value": f"Mention: <@{bot_id}>\n```Status: OFFLINE```",
                            "inline": False,
                        })
        finally:
            await client.close()

    await client.start(BOT_TOKEN)
    return issues


def send_alert(problems):
    if not problems:
        print("All services are online!")
        return

    embed = {
        "title": "🚨 Service Outage Detected",
        "description": "One or more monitored services failed their health check:",
        "color": 15548997,  # Red (#ED4245)
        "fields": problems,
        "footer": {"text": "GitHub Actions Uptime Monitor"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    payload = json.dumps({
        "username": "Outage Monitor",
        "embeds": [embed],
    }).encode("utf-8")

    req = urllib.request.Request(
        WEBHOOK_URL,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "StatusMonitor/1.0"},
        method="POST",
    )
    urllib.request.urlopen(req, timeout=10)


async def main():
    problems = []

    web_err = check_website(WEBSITE_URL)
    if web_err:
        problems.append(web_err)

    mc_err = check_minecraft(MC_SERVER_IP)
    if mc_err:
        problems.append(mc_err)

    bot_errs = await check_discord_bots()
    problems.extend(bot_errs)

    send_alert(problems)


if __name__ == "__main__":
    asyncio.run(main())
