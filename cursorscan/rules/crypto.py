"""Weak crypto rules: md5/sha1 unsafe usage, DES, ECB, fixed IV, hardcoded seeds.

Works at AST level for Python and JS/TS (via tree-sitter) and falls back to
regex for other languages / unparsed snippets.
"""

from __future__ import annotations

import re
from typing import List

from ..models import Evidence
from .helpers import code_lines

# --- helpers used by the shared scanner ------------------------------------

WEAK_HASH_CALLS = {
    "md5": "crypto.md5_or_sha1",
    "sha1": "crypto.md5_or_sha1",
    "MD5": "crypto.md5_or_sha1",
    "SHA1": "crypto.md5_or_sha1",
    "get_md5_insecure": "crypto.md5_or_sha1",
}

DES_NAMES = {"des", "des3", "DES", "DES3", "tripledes"}
ECB_NAMES = {"ecb", "ECB", "CipherMode.ECB"}
FIXED_IV_ARGS = {
    "iv",
    "nonce",
    "initialization_vector",
    "fixed_iv",
    "salt",
}

# hashlib constructors: hashlib.new("md5") etc.
WEAK_HASHlib_NEW = {"md5", "sha1"}
WEAK_HASHlib_ALGS = {"md5", "sha1"}

# JS crypto.subtle / node crypto weak choices
JS_WEAK = {
    "createHash",
    "pbkdf2",
    "scryptSync",
}

# --- regex fallbacks (non-Python/JS, or undecided) --------------------------

RE_MD5_CALL = re.compile(r"\b(authlib\.jose\.|Cryptodome\.Hash\.|Crypto\.Hash\.|hashlib\.(?:new\s*\(\s*[\"'])?)md5\b", re.I)
RE_SHA1_HASH = re.compile(r"\b(hashlib\.sha1|SHA1\b|Cryptodome\.Hash\.SHA1|Crypto\.Hash\.SHA1)")
RE_DES = re.compile(r"\b(des|des3|tripledes)\b", re.I)
RE_ECB = re.compile(r"\b(ecb|CipherMode\.ECB)\b", re.I)
RE_HARDCODED_IV = re.compile(
    r"\b(aes|cipher)(?:\.\w+|\s+\()\s*[^)\n]{0,40}(iv|nonce)\s*=\s*([\"'][^\"']+[\"']|b?[\"'][0-9a-fA-F]{8,}[\"']|[0-9]{5,})", re.I
)
RE_HARDCODED_SEED = re.compile(
    r"\b(random|torch|np?\.random|numpy\.random)(\.seed|\.manual_seed)\s*\(\s*(0|[1-9]\d{0,5}|-?[1-9])\s*\)"
)


def analyze_code(source_path: str, code: str) -> List[Evidence]:
    """Regex fallback for weak-crypto findings."""
    findings: List[Evidence] = []

    def hit(line: int, rule_id: str, title: str, message: str, fix: str, sev: str = "high") -> Evidence:
        return Evidence(
            rule_id=rule_id,
            title=title,
            severity=sev,
            file=source_path,
            line=line,
            message=message,
            fix=fix,
            dimension="crypto",
            code_snippet="",
        )

    for lineno, raw in code_lines(code):
        line = raw
        # Import / from-import lines are nothing but a name binding; real usage
        # of a weak algorithm is detected at call sites (regex + AST).
        if line.lstrip().startswith(("import ", "from ")):
            continue
        if RE_HARDCODED_SEED.search(line):
            findings.append(hit(lineno, "crypto.hardcoded_seed", "硬编码随机种子",
                                "随机数种子固定使输出可预测", "移除固定 seed 或从环境变量读取"))
        if RE_HARDCODED_IV.search(line):
            findings.append(hit(lineno, "crypto.fixed_iv", "固定 IV/nonce",
                                "加密使用固定初始化向量导致相同明文产生相同密文", "每次加密使用随机 IV"))
        if RE_MD5_CALL.search(line):
            findings.append(hit(lineno, "crypto.md5_or_sha1", "弱哈希算法 (MD5)",
                                "MD5 已被破解，不应用于安全场景", "改用 SHA-256 / SHA-3 (hashlib.sha256)"))
        if RE_SHA1_HASH.search(line):
            findings.append(hit(lineno, "crypto.md5_or_sha1", "弱哈希算法 (SHA1)",
                                "SHA-1 碰撞攻击成本已被学界证实", "改用 SHA-256 / SHA-3"))
        if RE_DES.search(line):
            findings.append(hit(lineno, "crypto.weak_cipher_des", "弱加密算法 (DES)",
                                "DES 密钥长度过短，易被暴力破解", "改用 AES (GCM 模式)"))
        if RE_ECB.search(line):
            findings.append(hit(lineno, "crypto.ecb_mode", "不安全加密模式 (ECB)",
                                "ECB 模式相同明文块产生相同密文块，泄露结构信息", "改用 GCM / CBC + 随机 IV"))
    return findings


# --- AST rules consumed by the tree-sitter walker ---------------------------
# Return list of Evidence given a language-agnostic dict describing the call.
def detect_weak_hash_py(values: dict, src: str) -> List[Evidence]:
    findings = []
    call = values.get("call")
    obj = values.get("obj", "")
    attr = values.get("attr", "")
    if obj in ("hashlib",) and attr in WEAK_HASHlib_NEW:
        findings.append(Evidence(
            rule_id="crypto.md5_or_sha1",
            title="弱哈希算法 (MD5/SHA1)",
            severity="high",
            file=values.get("file", ""),
            line=values.get("line", 1),
            message=f"hashlib.{attr} 用于非完整性校验场景",
            fix="改用 hashlib.sha256 / sha3_256",
            dimension="crypto",
        ))
    if attr == "new" and obj == "hashlib":
        # hashlib.new('md5') / hashlib.new('sha1')
        arg_text = values.get("args_text", "")
        if any(a in arg_text for a in ("'md5'", '"md5"', "'sha1'", '"sha1"')):
            findings.append(Evidence(
                rule_id="crypto.md5_or_sha1",
                title="弱哈希算法 (MD5/SHA1)",
                severity="high",
                file=values.get("file", ""),
                line=values.get("line", 1),
                message=f"hashlib.new({arg_text}) 调用弱哈希",
                fix="改用 hashlib.new('sha256')",
                dimension="crypto",
            ))
    return findings
