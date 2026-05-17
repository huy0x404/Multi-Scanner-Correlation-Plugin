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


def _to_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def get_dashboard_settings(dotenv_path: str | None = ".env") -> dict[str, str | bool | int]:
    dot_vals: dict[str, str] = {}
    if dotenv_path:
        dot_vals = _parse_dotenv(Path(dotenv_path))

    def _pick(key: str, default: str = "") -> str:
        return os.getenv(key) or dot_vals.get(key, default)

    return {
        "lang": _pick("MSCP_LANG", "en"),
        "risk_mode": _pick("MSCP_RISK_MODE", "realistic"),
        "analysis_engine": _pick("MSCP_ANALYSIS_ENGINE", "system"),
        "ai_enabled": _to_bool(_pick("MSCP_AI_ENABLED", "true"), default=True),
        "hf_api_key": _pick("HF_API_KEY", ""),
        "telegram_enabled": _to_bool(_pick("MSCP_TELEGRAM_ENABLED", "false")),
        "telegram_bot_token": _pick("TELEGRAM_BOT_TOKEN", ""),
        "telegram_chat_id": _pick("TELEGRAM_CHAT_ID", ""),
        "email_enabled": _to_bool(_pick("MSCP_EMAIL_ENABLED", "false")),
        "smtp_host": _pick("MSCP_SMTP_HOST", ""),
        "smtp_port": _pick("MSCP_SMTP_PORT", "587"),
        "smtp_user": _pick("MSCP_SMTP_USER", ""),
        "smtp_pass": _pick("MSCP_SMTP_PASS", ""),
        "email_from": _pick("MSCP_EMAIL_FROM", ""),
        "email_to": _pick("MSCP_EMAIL_TO", ""),
        "smtp_use_tls": _to_bool(_pick("MSCP_SMTP_USE_TLS", "true"), default=True),
    }
