"""Dependency risk (P3): known-vulnerable and unpinned packages in
requirements*.txt / package.json / go.mod.

Uses a small curated, static CVE table so it runs fully offline.  A pin at or
below a package's last-vulnerable release is flagged with its advisory; an
unpinned / floating specifier (``>=``, ``*``, ``latest`` ...) gets a low
severity reproducibility warning.  This is *not* a live advisory feed —
replacing the table with an OSV-style lookup is a future integration point.
"""

from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Optional, Tuple

from ..models import Evidence

DIMENSION = "dependencies"

# Lowercased package name -> [(last_vulnerable_version, CVE, severity, note)].
# A pinned version <= the last_vulnerable entry is reported.
KNOWN_VULNS: Dict[str, List[Tuple[str, str, str, str]]] = {
    "flask": [("0.12.2", "CVE-2018-1000656", "medium", "超大 JSON 数组导致 DoS (debug 模式)")],
    "jinja2": [("2.10.1", "CVE-2019-8341", "critical", "沙箱逃逸，可读取服务器文件 (SSTI)")],
    "django": [("1.11.27", "CVE-2019-19844", "high", "旧版 Django (1.11 已停止维护) 存在账户枚举漏洞")],
    "pillow": [("8.3.1", "CVE-2021-34552", "high", "convert 缓冲区溢出，可致 RCE")],
    "requests": [("2.19.1", "CVE-2018-18074", "medium", "重定向时不剥离 Authorization 头，凭据泄露")],
    "pyyaml": [("5.2", "CVE-2020-1747", "high", "yaml.load 加载不可信数据可致 RCE")],
    "cryptography": [("3.3.2", "CVE-2020-25659", "high", "RSA 解密 oracle 侧信道")],
    "urllib3": [("1.25.9", "CVE-2020-26137", "medium", "CRLF 注入 / HTTP 请求走私")],
    "pyjwt": [("1.6.4", "CVE-2018-1000531", "high", "算法混淆攻击，可伪造令牌")],
    "log4j": [("2.16.0", "CVE-2021-44228", "critical", "Log4Shell JNDI 注入 RCE")],
    "lodash": [("4.17.20", "CVE-2021-23337", "high", "defaultsDeep 原型污染")],
    "minimist": [("1.2.5", "CVE-2021-44906", "medium", "原型污染链可致 RCE")],
    "axios": [("0.21.1", "CVE-2021-3749", "high", "SSRF + 服务器端请求认证绕过")],
    "moment": [("2.29.3", "CVE-2022-31129", "medium", "duration 解析 ReDoS")],
    "yargs-parser": [("18.1.1", "CVE-2020-7608", "medium", "原型污染")],
    # Go module versions (no leading v in the last-vulnerable marker).
    "gopkg.in/yaml.v2": [("2.2.8", "CVE-2019-11254", "high", "yaml.Unmarshal 超大别名表 DoS")],
    "github.com/dgrijalva/jwt-go": [("3.2.0", "CVE-2020-26160", "high", "jwt-go 越界读，可致进程 panic")],
    "github.com/gorilla/websocket": [("1.4.2", "CVE-2020-27813", "medium", "WebSocket 握手竞态信息泄露")],
    "github.com/valyala/fasthttp": [("1.33.0", "CVE-2022-21221", "high", "fasthttp 请求走私 (CRLF)")],
    "github.com/hashicorp/go-retryablehttp": [("0.7.1", "CVE-2022-46773", "medium", "日志中泄露 Authorization 头")],
    "github.com/spf13/cobra": [("1.0.0", "CVE-2019-19551", "medium", "spf13/cobra 命令注入 (旧 bound 参数)")],
}


# --------------------------------------------------------------------------
# Version comparison
# --------------------------------------------------------------------------

def _ver_tuple(version: str) -> Optional[Tuple[int, ...]]:
    """Leading dotted-numeric prefix as an int tuple, else None."""
    m = re.match(r"^\s*v?(\d+(?:\.\d+)*)", str(version))
    if not m:
        return None
    return tuple(int(p) for p in m.group(1).split("."))


def _cmp(a: str, b: str) -> Optional[int]:
    """-1 / 0 / 1 when both versions parse (pad to equal width), else None."""
    ta, tb = _ver_tuple(a), _ver_tuple(b)
    if ta is None or tb is None:
        return None
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def _known_vuln(name: str, version: str) -> Optional[Tuple[str, str, str]]:
    """Return (CVE, severity, note) when ``version`` is at/below a known release."""
    for max_vul, cve, sev, note in KNOWN_VULNS.get(name.lower(), ()):
        c = _cmp(version, max_vul)
        if c is not None and c <= 0:
            return cve, sev, note
    return None


# --------------------------------------------------------------------------
# Evidence building
# --------------------------------------------------------------------------

def _evidence(path: str, line: int, rule_id: str, title: str,
              msg: str, fix: str, sev: str) -> Evidence:
    return Evidence(rule_id=rule_id, title=title, severity=sev, file=path,
                    line=line, message=msg, fix=fix, dimension=DIMENSION)


def _vuln_evidence(path: str, line: int, name: str, spec: str,
                   cve: str, sev: str, note: str) -> Evidence:
    return _evidence(
        path, line, "deps.known_vulnerable", "依赖存在已知漏洞",
        f"{name}{spec} 命中 {cve}: {note}",
        f"升级 {name} 到修复版本（参考 {cve} 公告）", sev)


def _unpinned_evidence(path: str, line: int, name: str, spec: str) -> Evidence:
    return _evidence(
        path, line, "deps.unpinned_package", "未固定版本的依赖",
        f"{name} 使用未固定版本（{spec}），构建不可复现且可能引入含漏洞版本",
        "锁定精确版本（requirements: ==；npm: 配合 lockfile）", "low")


# --------------------------------------------------------------------------
# requirements*.txt
# --------------------------------------------------------------------------

_REQ_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*(==|>=|<=|~=|!=|>|<|===)?\s*([^\s;]+)?")
_REQ_SKIP = re.compile(r"^\s*[#\-]")


def _parse_pin(spec: str) -> Tuple[Optional[str], bool]:
    """Return (version, exact) for a requirements spec; exact==True only for ==."""
    m = _REQ_RE.match(spec)
    if not m:
        return None, False
    _, op, version = m.groups()
    return version, op in ("==", "===")


def _check_requirements(path: str, code: str, findings: List[Evidence]) -> None:
    for lineno, raw in enumerate(code.splitlines(), start=1):
        if not raw.strip() or _REQ_SKIP.match(raw):
            continue
        m = _REQ_RE.match(raw)
        if not m:
            continue
        name, op, version = m.groups()
        if not version or op not in ("==", "==="):
            findings.append(_unpinned_evidence(path, lineno, name, raw.strip()))
            continue
        vuln = _known_vuln(name, version)
        if vuln:
            findings.append(_vuln_evidence(path, lineno, name, f"=={version}", *vuln))


# --------------------------------------------------------------------------
# package.json
# --------------------------------------------------------------------------

_FLOATING = ("*", "latest", "next", "x")


def _is_floating(spec: str) -> bool:
    s = spec.strip()
    return s in _FLOATING or s.endswith(".x") or s.startswith((">", "<"))


def _exact_npm_version(spec: str) -> Optional[str]:
    """Exact pins only (bare or ``=``); ranges like ^/~ never qualify."""
    s = spec.strip()
    if s.startswith(("^", "~", ">", "<")) or s in _FLOATING or s.endswith(".x"):
        return None
    m = re.match(r"=?v?(\d+(?:\.\d+)*)", s)
    if not m:
        return None
    return m.group(1)


def _find_dep_line(source_lines: List[str], name: str) -> int:
    pat = re.compile('"' + re.escape(name) + r'"\s*:')
    for i, line in enumerate(source_lines, start=1):
        if pat.search(line):
            return i
    return 1


def _check_package_json(path: str, code: str, findings: List[Evidence]) -> None:
    try:
        doc = json.loads(code)
    except ValueError:
        return  # malformed manifest: not part of this rule's scope
    if not isinstance(doc, dict):
        return
    source_lines = code.splitlines()
    for section in ("dependencies", "devDependencies"):
        deps = doc.get(section)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if not isinstance(spec, str):
                continue
            lineno = _find_dep_line(source_lines, name)
            version = _exact_npm_version(spec)
            if version is None:
                if _is_floating(spec):
                    findings.append(_unpinned_evidence(path, lineno, name, spec))
                continue
            vuln = _known_vuln(name, version)
            if vuln:
                findings.append(_vuln_evidence(path, lineno, name, f"@{spec}", *vuln))


# --------------------------------------------------------------------------
# go.mod
# --------------------------------------------------------------------------

# A Go module require line: path + a version (usually v-prefixed).
_GO_REQUIRE_RE = re.compile(r'^\s*([A-Za-z0-9_.\-/]+)\s+(v?\d+(?:\.\d+)*[^ \t]*)')


def _check_go_mod(path: str, code: str, findings: List[Evidence]) -> None:
    for lineno, raw in enumerate(code.splitlines(), start=1):
        s = raw.strip()
        if not s or s.startswith("//") or s.startswith("module ") \
                or s.startswith("go ") or s.startswith("require ("):
            continue
        if s == ")":
            continue
        # Drop trailing comments; unwrap a single-line `require pkg vX`.
        body = s.split("//", 1)[0].strip()
        if body.startswith("require "):
            body = body[len("require "):].strip()
        m = _GO_REQUIRE_RE.match(body)
        if not m:
            continue
        name, version = m.groups()
        # Only exact v-prefixed (or bare plain) pins; no +incompatible markers.
        base = version.split("+")[0]
        if not base.startswith("v") and not re.match(r"^\d+(\.\d+)+$", base):
            continue
        clean = base.lstrip("v")
        vuln = _known_vuln(name, clean)
        if vuln:
            findings.append(_vuln_evidence(path, lineno, name, " " + version, *vuln))


# --------------------------------------------------------------------------
# Public entry point (per-file rule, runs on every text file)
# --------------------------------------------------------------------------

def analyze_code(source_path: str, code: str) -> List[Evidence]:
    findings: List[Evidence] = []
    base = os.path.basename(source_path).lower()
    if base == "package.json":
        _check_package_json(source_path, code, findings)
    elif (base == "requirements.txt" or base == "requirement.txt"
          or (base.startswith("requirements") and base.endswith(".txt"))):
        _check_requirements(source_path, code, findings)
    elif base == "go.mod":
        _check_go_mod(source_path, code, findings)
    return findings
