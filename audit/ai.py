from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass

from .findings import Finding


SECRET_PATTERN = re.compile(r"(?i)(password|passwd|secret|api[_-]?key|token)\s*([=:])\s*([^\s,;]+)")


@dataclass(slots=True)
class AIConfig:
    endpoint: str
    model: str
    api_key: str
    level: str = "beginner"


def config_from_env(level: str = "beginner") -> AIConfig | None:
    endpoint = os.getenv("JAVA_AUDIT_AI_ENDPOINT", "").rstrip("/")
    model = os.getenv("JAVA_AUDIT_AI_MODEL", "")
    api_key = os.getenv("JAVA_AUDIT_AI_KEY", "")
    if not endpoint or not model:
        return None
    return AIConfig(endpoint, model, api_key, level)


def explain_with_ai(finding: Finding, config: AIConfig) -> dict[str, object]:
    """Send only one redacted finding. The model may explain, never confirm the vulnerability."""
    evidence = SECRET_PATTERN.sub(r"\1\2[REDACTED]", finding.evidence)
    prompt = {
        "role": "Java 安全审计学习教练",
        "audience": config.level,
        "constraint": "只能根据证据解释待复核假设，不得声称漏洞已经确认。返回 JSON。",
        "finding": {"cwe": finding.cwe, "rule": finding.rule_id, "description": finding.description, "evidence": evidence, "review_steps": finding.review_steps},
        "output": {"explanation": "string", "questions": ["string"], "safe_example": "string", "uncertainties": ["string"]},
    }
    request_body = json.dumps({
        "model": config.model,
        "messages": [{"role": "user", "content": json.dumps(prompt, ensure_ascii=False)}],
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
    }).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if config.api_key:
        headers["Authorization"] = f"Bearer {config.api_key}"
    request = urllib.request.Request(f"{config.endpoint}/chat/completions", data=request_body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = json.loads(response.read().decode("utf-8"))
        content = payload["choices"][0]["message"]["content"]
        return json.loads(content)
    except (urllib.error.URLError, TimeoutError, KeyError, IndexError, json.JSONDecodeError) as exc:
        return {"error": str(exc), "uncertainties": ["AI 解释生成失败，保留规则证据供人工复核。"]}
