from __future__ import annotations

import json
from urllib import parse, request


def send_telegram_alert(bot_token: str, chat_id: str, message: str) -> None:
    payload = parse.urlencode({"chat_id": chat_id, "text": message}).encode("utf-8")
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

    req = request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    with request.urlopen(req, timeout=8) as resp:
        body = resp.read().decode("utf-8", errors="ignore")
        data = json.loads(body)
        if not data.get("ok", False):
            raise RuntimeError(f"Telegram API error: {data}")
