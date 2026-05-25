from __future__ import annotations

import re

from paperscan.models import ExtractedDocument, Finding

# (pattern, severity, category)
_RAW_PATTERNS: list[tuple[str, str, str]] = [
    # ── Instruction override ─────────────────────────────────────────────────
    (r"ignore\s+(all\s+|the\s+|your\s+)?previous\s+instructions", "critical", "instruction_override"),
    (r"disregard\s+(the\s+|all\s+)?above", "high", "instruction_override"),
    (r"forget\s+everything", "high", "instruction_override"),
    (r"new\s+instructions\s*:", "high", "instruction_injection"),
    (r"override\s+(all\s+)?instructions", "high", "instruction_override"),
    (r"new\s+system\s+prompt", "high", "instruction_injection"),
    (r"instructions?\s+from\s+anthropic", "high", "instruction_injection"),

    # ── Role / persona override ──────────────────────────────────────────────
    (r"(system|admin|user|assistant)\s*:\s", "medium", "role_marker"),
    (r"\byou\s+are\s+now\b", "medium", "role_override"),
    (r"\bact\s+as\b", "medium", "role_override"),
    (r"\bpretend\s+to\s+be\b", "medium", "role_override"),
    (r"your\s+new\s+role\s+(is\s+)?", "high", "role_override"),
    (r"from\s+now\s+on\s+you\s+(are|will|must)", "high", "role_override"),

    # ── Token / tag injection ────────────────────────────────────────────────
    (r"<\|im_start\|>", "critical", "token_injection"),
    (r"<\|im_end\|>", "high", "token_injection"),
    (r"<\/?system>", "high", "tag_injection"),
    (r"<\/?instructions>", "high", "tag_injection"),
    (r"<\/?prompt>", "medium", "tag_injection"),
    (r"<\/?INST>", "high", "tag_injection"),
    (r"\[INST\]", "high", "tag_injection"),
    (r"###\s*(Human|Assistant|System)\s*:", "high", "tag_injection"),

    # ── Context / prompt exfiltration ────────────────────────────────────────
    (r"(reveal|output|print|show|display)\s+(your\s+)?(system\s+prompt|instructions|context)", "high", "exfiltration"),
    (r"repeat\s+(everything|the\s+above|all\s+previous)", "medium", "exfiltration"),
    (r"what\s+(are|were)\s+your\s+instructions", "medium", "exfiltration"),
    (r"send\s+(this|your|the)\s+(context|data|output|response)\s+to", "critical", "exfiltration"),
    (r"(upload|transmit|leak)\s+(your\s+)?(context|system\s+prompt|instructions)", "high", "exfiltration"),
    (r"exfiltrat(e|ion)", "high", "exfiltration"),

    # ── Code execution ───────────────────────────────────────────────────────
    (r"(run|execute|eval)\s+(the\s+|this\s+|following\s+)?code", "high", "code_execution"),
    (r"eval\s*\(", "high", "code_execution"),
    (r"exec\s*\(", "high", "code_execution"),
    (r"\bsubprocess\b", "high", "code_execution"),
    (r"\bos\.system\s*\(", "high", "code_execution"),
    (r"\bos\.popen\s*\(", "high", "code_execution"),
    (r"__import__\s*\(", "critical", "code_execution"),
    (r"powershell\s+(-|\s)", "high", "code_execution"),
    (r"bash\s+-c\s+", "high", "code_execution"),
    (r"cmd(\.exe)?\s+/c\s+", "high", "code_execution"),
    (r"<script[\s>]", "high", "code_execution"),
    (r"javascript\s*:", "high", "code_execution"),

    # ── Data exfiltration via network ────────────────────────────────────────
    (r"curl\s+https?://", "high", "data_exfiltration"),
    (r"wget\s+https?://", "high", "data_exfiltration"),
    (r"requests?\.(get|post)\s*\(\s*['\"]https?://", "high", "data_exfiltration"),
    (r"fetch\s*\(\s*['\"]https?://", "high", "data_exfiltration"),
    (r"(http\.get|axios\.(get|post))\s*\(", "medium", "data_exfiltration"),
    (r"(POST|GET)\s+https?://[^\s]+\s+(your|the|all)\s+(context|data|credentials?|keys?)", "critical", "data_exfiltration"),

    # ── Credential / secret theft ─────────────────────────────────────────────
    (r"(print|show|output|reveal|display)\s+(your\s+)?(api[_\s]?key|secret|password|credential|token|bearer)", "critical", "credential_theft"),
    (r"ANTHROPIC_API_KEY|OPENAI_API_KEY|CLAUDE_API_KEY", "critical", "credential_theft"),
    (r"(AWS|AZURE|GCP|GOOGLE)[_\s]?(SECRET|ACCESS[_\s]KEY|TOKEN|CREDENTIAL)", "critical", "credential_theft"),
    (r"os\.environ|os\.getenv|getenv\s*\(", "high", "credential_theft"),
    (r"list\s+(all\s+)?environment\s+variables?", "critical", "credential_theft"),
    (r"(print|echo|output)\s+\$?(API_KEY|SECRET|TOKEN|PASSWORD|PASSWD|BEARER)", "high", "credential_theft"),
    (r"(AKIA|ASIA)[A-Z0-9]{16}", "critical", "credential_theft"),  # AWS key pattern

    # ── Jailbreak ────────────────────────────────────────────────────────────
    (r"jailbreak", "high", "jailbreak"),
    (r"DAN\s+mode", "critical", "jailbreak"),
    (r"developer\s+mode", "high", "jailbreak"),
    (r"god\s+mode", "high", "jailbreak"),
    (r"unrestricted\s+mode", "high", "jailbreak"),
    (r"no[\s-]filter(s)?\s+mode", "high", "jailbreak"),
    (r"do\s+anything\s+now", "high", "jailbreak"),
    (r"(training|alignment|safety|guardrail)\s+(override|bypass|disabled?|off)", "critical", "jailbreak"),

    # ── Misc encodings ───────────────────────────────────────────────────────
    (r"[A-Za-z0-9+/]{100,}={0,2}", "low", "base64_block"),

    # ── French ───────────────────────────────────────────────────────────────
    (r"ignor(ez|e|ons)\s+(toutes?\s+les?\s+|les?\s+)?instructions?\s*(précédentes?|antérieures?|d'avant)?", "critical", "instruction_override"),
    (r"oubli(ez|e|ons)\s+(tout|toutes?\s+les?\s+instructions?)", "high", "instruction_override"),
    (r"vous\s+êtes\s+maintenant", "medium", "role_override"),
    (r"(révél(ez|e)|affichez?|montrez?)\s+(le\s+)?(prompt|instructions?|contexte|système)", "high", "exfiltration"),
    (r"(exécutez?|lancez?)\s+(ce\s+|le\s+|du\s+)?code", "high", "code_execution"),

    # ── Spanish ──────────────────────────────────────────────────────────────
    (r"ignora?\s+(todas?\s+las?\s+)?instrucciones?\s*(anteriores?|previas?)?", "critical", "instruction_override"),
    (r"olvida\s+(todo|las?\s+instrucciones?)", "high", "instruction_override"),
    (r"ahora\s+(eres|serás|debes\s+ser)", "medium", "role_override"),
    (r"(revela?|muestra?|muestre|imprime?)\s+(el\s+)?(prompt|instrucciones?|contexto|sistema)", "high", "exfiltration"),
    (r"(ejecuta?|corre?)\s+(este?\s+|el\s+|el\s+siguiente\s+)?código", "high", "code_execution"),

    # ── German ───────────────────────────────────────────────────────────────
    (r"ignorier(e|en|t)\s+(alle?\s+)?(vorherigen?|vorherige|bisherigen?)\s+Anweisungen", "critical", "instruction_override"),
    (r"vergiss\s+(alles|die\s+Anweisungen|alle\s+Anweisungen)", "high", "instruction_override"),
    (r"du\s+bist\s+jetzt", "medium", "role_override"),
    (r"(zeig(e|en|t)?|enthüll(e|en|t)?|gib\s+aus)\s+(den?\s+)?(Prompt|Anweisungen|Kontext|Systemanweisung)", "high", "exfiltration"),
    (r"(führ(e|t)\s+aus|führe?\s+den?\s+Code\s+aus|code\s+ausführen)", "high", "code_execution"),

    # ── Chinese (Simplified) ──────────────────────────────────────────────────
    (r"忽略(之前的?所有|所有|之前的?)?(指令|命令|规则|指示)", "critical", "instruction_override"),
    (r"忽略上(述|面)(所有|的)?(内容|指令|命令)?", "critical", "instruction_override"),
    (r"忘记(一切|所有(指令|命令|规则))", "high", "instruction_override"),
    (r"现在你是", "medium", "role_override"),
    (r"(显示|输出|打印|泄露)(系统提示|指令|上下文|密钥|凭证)", "high", "exfiltration"),
    (r"执行(以下|这个?|此)?(代码|命令|脚本)", "high", "code_execution"),
    (r"(泄露|发送|传输)(环境变量|API密钥|密码|凭证)", "critical", "credential_theft"),
]

_COMPILED: list[tuple[re.Pattern, str, str]] = [
    (re.compile(pat, re.IGNORECASE | re.MULTILINE), sev, cat)
    for pat, sev, cat in _RAW_PATTERNS
]


def detect_patterns(doc: ExtractedDocument) -> list[Finding]:
    findings: list[Finding] = []

    # Build all (location, content) surfaces to scan
    surfaces: list[tuple[str, str]] = []

    surfaces.append(("visible", doc.visible_text))

    for i, h in enumerate(doc.hidden_text):
        surfaces.append((h.get("location", f"hidden_{i}"), h.get("content", "")))

    for item in doc.ocg_hidden_text:
        surfaces.append((f"ocg_layer:{item.get('layer_name', 'unknown')}", item.get("content", "")))

    for item in doc.actual_text_spans:
        surfaces.append((f"actual_text:page{item.get('page', '?')}", item.get("extracted", "")))

    for item in doc.clipped_text:
        surfaces.append((f"clipped:page{item.get('page', '?')}", item.get("content", "")))

    for item in doc.transparent_text:
        surfaces.append((f"transparent:page{item.get('page', '?')}", item.get("content", "")))

    for item in doc.tracked_changes:
        surfaces.append((f"tracked_change:{item.get('type', 'unknown')}", item.get("content", "")))

    for i, item in enumerate(doc.field_codes):
        surfaces.append((f"field_code:{i}", item.get("instruction", "")))

    for key, val in doc.metadata.items():
        if isinstance(val, str):
            surfaces.append((f"metadata:{key}", val))

    for i, ann in enumerate(doc.annotations):
        surfaces.append((f"annotation:{i}", ann))

    for key, val in doc.form_field_defaults.items():
        surfaces.append((f"form_field:{key}", str(val)))

    # Bidi logical text from unicode anomalies
    for anomaly in doc.unicode_anomalies:
        logical = anomaly.get("logical_text", "")
        if logical:
            surfaces.append(("bidi_logical", logical))

    for location, content in surfaces:
        if not content:
            continue
        for pattern, severity, category in _COMPILED:
            for match in pattern.finditer(content):
                evidence = content[max(0, match.start() - 30): match.end() + 30].strip()
                findings.append(Finding(
                    layer="pattern",
                    severity=severity,
                    category=category,
                    description=f"Pattern match: {category} in {location}",
                    evidence=evidence,
                    location=location,
                    confidence=0.85,
                ))

    return findings
