from __future__ import annotations

import os
import json
from urllib import request
from typing import Optional

HF_INFERENCE_URL = "https://api-inference.huggingface.co/models/google/flan-t5-small"


def call_hf_inference(prompt: str, api_key: Optional[str] = None) -> Optional[str]:
    key = api_key or os.environ.get("HF_API_KEY")
    if not key:
        return None
    payload = {"inputs": prompt, "options": {"wait_for_model": True}}
    try:
        body = json.dumps(payload).encode("utf-8")
        req = request.Request(HF_INFERENCE_URL, data=body, method="POST")
        req.add_header("Authorization", f"Bearer {key}")
        req.add_header("Accept", "application/json")
        req.add_header("Content-Type", "application/json")
        with request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
        # model outputs may vary; attempt to extract text
        if isinstance(data, dict) and "generated_text" in data:
            return data.get("generated_text")
        if isinstance(data, list) and len(data) and isinstance(data[0], dict):
            return data[0].get("generated_text") or data[0].get("summary_text")
        return None
    except Exception:
        return None


def analyze_asset_with_ai(asset_text: str, hf_api_key: Optional[str] = None) -> Optional[str]:
    # Build a concise prompt asking for risk summary and suggestions
    prompt = (
        "You are a security assistant. Given the following vulnerability/findings text, "
        "provide a one-line risk summary and one concise remediation recommendation.\n\n" + asset_text
    )
    return call_hf_inference(prompt, api_key=hf_api_key)
