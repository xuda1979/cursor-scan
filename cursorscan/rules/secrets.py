"""Hardcoded secret detection: AWS keys, tokens, private keys, generic password/key assignments.

Pure regex + heuristics over source text, applying to all text files so it
works outside parsed languages too. Kept conservative to avoid false positives.
"""

from __future__ import annotations

import re
from typing import List

from ..models import Evidence
from .helpers import code_lines

RE_AWS_AKEY = re.compile(r"\b(AKIA|ASIA|ABCDEFGHIJKLMNOPQRSTUVWXYZ)[A-Z0-9]{16,20}\b")
RE_AWS_SKEY = re.compile(r"\b[A-Za-z0-9/+=]{40}\b")
# Names that identify a variable as an AWS secret access key. A 40-char value
# alone is ambiguous, so the paired rule only fires when one of these (or a
# nearby access key ID) is present. The lookahead keeps ``aws_secretary``-style
# longer identifiers from matching via the ``aws_secret`` branch.
RE_AWS_SECRET_CONTEXT = re.compile(
    r"(?:aws[_-]?secret(?:[_-]?access[_-]?key)?|secret[_-]?access[_-]?key)(?![A-Za-z0-9])",
    re.I,
)
RE_SLACK_TOKEN = re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")
RE_GITHUB_TOKEN = re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")
RE_GOOGLE_API = re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")
RE_JWT_GENERIC = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.([A-Za-z0-9_-]{8,})?")
RE_STRIPE = re.compile(r"\b(sk_live_[0-9A-Za-z]{20,}|rk_live_[0-9A-Za-z]{20,})\b")
RE_PEM_PRIVATE = re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
RE_OP_SSH = re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----")
RE_GENERIC_KEY = re.compile(
    r"""^\s*(?:export\s+)?(?P<key>[A-Za-z_][A-Za-z0-9_]{1,31})\s*[=:]\s*(?P<val>["']?[A-Za-z0-9_\-./!@#$%^&*+=?]{10,}["']?)\s*$"""
)

# Keys hinting at a credential. Segments are matched on underscore boundaries
# so ``api_key``, ``db_password`` and ``auth_token`` all hit while ``monkey``
# or ``key_press``-style names do not; entropy/placeholder guards below keep
# the rule conservative.
STRONG_HINT_KEYS = re.compile(
    r"(?:^|_)(?:api|access|secret|token|password|passwd|pwd|private|client|"
    r"credential|auth|pem|salt|key)(?:_|$)",
    re.I,
)
LOW_ENTROPY = re.compile(
    r"""^["'"?]+$|^[0-9]{1,6}$|^(true|false|null|none|xxx|changeme|change_me|example|test|default)$|^[x*]{4,}$""",
    re.I,
)

# Obfuscation / placeholder values we never flag.
PLACEHOLDER_VALUES = re.compile(
    r"^(your|my|example|sample|demo|replace|test|dummy|fake|changeme|change-me|local|prod|staging|dev|default|foo|bar|\.\.\.|xxxxx+)\w*$|^\{\{\w+\}\}$|^env\(.+\)$|^process\.env\..+$|^os\.environ\.get\(.+\)$|\$",
    re.I,
)


def analyze_code(source_path: str, code: str) -> List[Evidence]:
    findings: List[Evidence] = []

    def hit(line: int, rule_id: str, title: str, msg: str, fix: str, sev: str = "critical") -> Evidence:
        return Evidence(rule_id=rule_id, title=title, severity=sev, file=source_path,
                        line=line, message=msg, fix=fix, dimension="secrets")

    # PEM/SSH private keys usually live inside triple-quoted strings, which
    # code_lines drops — scan raw lines first for the BEGIN/END markers.
    if RE_PEM_PRIVATE.search(code) or RE_OP_SSH.search(code):
        for lineno, raw in enumerate(code.splitlines(), start=1):
            if RE_PEM_PRIVATE.search(raw) or RE_OP_SSH.search(raw):
                findings.append(hit(lineno, "secrets.private_key", "硬编码私钥",
                                    "源码中发现 PEM/OpenSSH 私钥块", "移除私钥，移动到密钥管理 (如环境变量 / KMS)"))

    for lineno, raw in code_lines(code):
        stripped = raw.strip()
        # Skip obvious comments only.
        if stripped.startswith("#"):
            continue
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            continue

        if RE_PEM_PRIVATE.search(raw) or RE_OP_SSH.search(raw):
            findings.append(hit(lineno, "secrets.private_key", "硬编码私钥",
                                "源码中发现 PEM/OpenSSH 私钥块", "移除私钥，移动到密钥管理 (如环境变量 / KMS)"))
            continue

        if RE_STRIPE.search(raw):
            findings.append(hit(lineno, "secrets.stripe_key", "硬编码 Stripe 密钥",
                                "检测到 live Stripe key", "使用环境变量 / 密钥管理"))
            continue
        if RE_GITHUB_TOKEN.search(raw):
            findings.append(hit(lineno, "secrets.github_token", "硬编码 GitHub Token",
                                "检测到 GitHub token", "改用环境变量，撤销泄露 token"))
            continue
        if RE_SLACK_TOKEN.search(raw):
            findings.append(hit(lineno, "secrets.slack_token", "硬编码 Slack Token",
                                "检测到 Slack bot token", "使用环境变量"))
            continue
        if RE_GOOGLE_API.search(raw):
            findings.append(hit(lineno, "secrets.google_api_key", "硬编码 Google API Key",
                                "检测到 Google API key", "使用环境变量 / Google Secret Manager"))
            continue
        if RE_AWS_AKEY.search(raw):
            findings.append(hit(lineno, "secrets.aws_access_key", "硬编码 AWS 访问密钥 ID",
                                "检测到 AWS Access Key ID", "移除，使用 IAM 角色 / AWS Secrets Manager"))
        # AWS secret access keys are 40-char base64-ish strings with no stable
        # prefix, so a bare match is too noisy to flag. Only report when the
        # line also names the credential (``aws_secret_access_key=...``) or
        # carries the access key ID it pairs with.
        if RE_AWS_SKEY.search(raw) and (RE_AWS_SECRET_CONTEXT.search(raw) or RE_AWS_AKEY.search(raw)):
            findings.append(hit(lineno, "secrets.aws_secret_key", "硬编码 AWS 秘密访问密钥",
                                "检测到 AWS Secret Access Key", "移除，使用 IAM 角色 / AWS Secrets Manager / 环境变量"))

        # Generic KEY = value assignment
        m = RE_GENERIC_KEY.match(raw)
        if m:
            key, val = m.group("key"), m.group("val")
            if STRONG_HINT_KEYS.search(key):
                cleaned = val.strip("'\"")
                if LOW_ENTROPY.match(cleaned) or PLACEHOLDER_VALUES.search(cleaned):
                    continue
                if len(cleaned) < 10:
                    continue
                findings.append(hit(lineno, "secrets.hardcoded_key", "硬编码密钥/口令",
                                    f"变量 {key} 被赋为硬编码值", "改为从环境变量 / 密钥管理读取",
                                    sev="high"))
    return findings
