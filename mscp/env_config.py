from __future__ import annotations

import os
from pathlib import Path


def _parse_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values

    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key:
                values[key] = value
    return values


def get_telegram_config(dotenv_path: str | None = ".env") -> tuple[str | None, str | None]:
    env_token = os.getenv("TELEGRAM_BOT_TOKEN")
    env_chat = os.getenv("TELEGRAM_CHAT_ID")

    if env_token and env_chat:
        return env_token, env_chat

    dot_vals: dict[str, str] = {}
    if dotenv_path:
        dot_vals = _parse_dotenv(Path(dotenv_path))

    token = env_token or dot_vals.get("TELEGRAM_BOT_TOKEN")
    chat = env_chat or dot_vals.get("TELEGRAM_CHAT_ID")
    return token, chat
