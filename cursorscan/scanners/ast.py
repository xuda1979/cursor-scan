"""AST scanners for Python and JS/TS built on tree-sitter.

Each scanner visits the parsed tree and emits Evidence objects. The scanners
operate on source text plus a few tree-sitter node helpers; where an AST-based
check is ambiguous (e.g. fixed IV, ECB) we fall back to line-oriented regex.
"""

from __future__ import annotations

import re

import tree_sitter_javascript
import tree_sitter_python
import tree_sitter_typescript
from tree_sitter import Language, Parser

from ..models import Evidence

_LANG_CACHE: dict = {}


def _language(name: str):
    if name not in _LANG_CACHE:
        if name == "python":
            lang = Language(tree_sitter_python.language())
        elif name == "javascript":
            lang = Language(tree_sitter_javascript.language())
        else:  # typescript
            lang = Language(tree_sitter_typescript.language_typescript())
        _LANG_CACHE[name] = lang
    return _LANG_CACHE[name]


_PARSER_CACHE: dict = {}
_ext_to_lang = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
}


def lang_for_file(path: str):
    import os
    low = path.lower()
    for ext, lang in _ext_to_lang.items():
        if low.endswith(ext):
            return lang
    return None


def _parser(lang: str) -> Parser:
    if lang not in _PARSER_CACHE:
        _PARSER_CACHE[lang] = Parser(_language(lang))
    return _PARSER_CACHE[lang]


def parse(source: str, lang: str):
    return _parser(lang).parse(source.encode("utf-8", errors="surrogatepass"))


def collect_calls(root, src: str):
    """Yield (call_node) for every call node in the tree.

    Python grammar names calls ``call``; the JS/TS grammars use
    ``call_expression``.
    """
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type in ("call", "call_expression"):
            yield node
        stack.extend(node.children)


def collect_new_expressions(root):
    """Yield every ``new_expression`` node (JS ``new Foo(...)``).

    tree-sitter models ``new Function(body)`` as a ``new_expression`` with a
    ``constructor`` field, never as a ``call_expression``, so ``collect_calls``
    cannot see it -- ``Function`` is the constructor-equivalent of ``eval`` and
    must be inspected on its own pass.
    """
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "new_expression":
            yield node
        stack.extend(node.children)


def new_expression_name(node, src: str) -> str:
    """Textual constructor name of a ``new_expression``, e.g. ``Function``."""
    ctor = node.child_by_field_name("constructor")
    if ctor is None:
        return ""
    return src[ctor.start_byte:ctor.end_byte]


def call_fn_name(node, src: str) -> str:
    """Return textual form of call function, e.g. 'hashlib.md5', 'yaml.load'."""
    fn = node.child_by_field_name("function")
    if fn is None:
        return ""
    return src[fn.start_byte:fn.end_byte]


def args_text(node, src: str) -> str:
    args = node.child_by_field_name("arguments")
    if args is None:
        return ""
    return src[args.start_byte:args.end_byte]


def _line_for(node) -> int:
    return node.start_point[0] + 1


def _ev(rule_id, title, sev, path, line, msg, fix, dimension):
    return Evidence(rule_id=rule_id, title=title, severity=sev, file=path, line=line,
                    message=msg, fix=fix, dimension=dimension)


# --------------------------------------------------------------------------
# Python AST analysis
# --------------------------------------------------------------------------

def analyze_python(path, src, findings):
    tree = parse(src, "python")
    root = tree.root_node
    for call in collect_calls(root, src):
        fn = call_fn_name(call, src)
        args = args_text(call, src)
        line = _line_for(call)

        # ----- weak crypto -----
        if fn in ("hashlib.md5", "hashlib.sha1", "md5", "sha1",
                  "hashlib.new", "cryptography.hazmat.primitives.hashes.MD5",
                  "cryptography.hazmat.primitives.hashes.SHA1"):
            if fn.startswith("hashlib.new"):
                if any(q in args for q in ('"md5"', "'md5'", '"sha1"', "'sha1'")):
                    findings.append(_ev(
                        "crypto.md5_or_sha1", "弱哈希算法 (MD5/SHA1)", "high", path, line,
                        f"hashlib.new 调用弱哈希 {args}", "改用 sha256", "crypto"))
            elif fn == "md5" or fn == "sha1":
                # bare md5()/sha1() is fine only if definition; but this is a call so flag
                findings.append(_ev(
                    "crypto.md5_or_sha1", "弱哈希算法 (MD5/SHA1)", "medium", path, line,
                    f"调用 md5/sha1: {fn}()", "改用 sha256", "crypto"))
            else:
                findings.append(_ev(
                    "crypto.md5_or_sha1", "弱哈希算法 (MD5/SHA1)", "high", path, line,
                    f"调用弱哈希 {fn}", "改用 sha256 (hashlib.sha256)", "crypto"))
        if fn in ("hmac.new", "hmac.HMAC"):
            digest = None
            kw = _find_kw_literal(call, src, ("digestmod",))
            if kw is not None:
                digest = _py_static_string(kw[0])  # digestmod="md5"
            else:
                pos = _py_positional_args(call, src)
                if len(pos) >= 3:
                    digest = _py_static_string(pos[2])  # hmac.new(key, msg, "md5")
            if digest is not None and digest.lower() in ("md5", "sha1"):
                findings.append(_ev(
                    "crypto.md5_or_sha1", "弱哈希算法 (MD5/SHA1)", "high", path, line,
                    f"HMAC 使用弱摘要 {digest}: {fn}({args})", "改用 sha256 摘要", "crypto"))

        # ------ weak cipher / mode ------
        if fn in ("AES.new", "AES", "DES.new", "DES3.new", "DES", "TripleDES.new",
                  "Crypto.Cipher.DES.new", "Crypto.Cipher.DES3.new",
                  "cryptography.hazmat.primitives.ciphers.algorithms"):
            if "MODE.ECB" in args or "ECB" in args:
                findings.append(_ev(
                    "crypto.ecb_mode", "不安全加密模式 (ECB)", "high", path, line,
                    f"{fn} 使用 ECB 模式", "改用 GCM/CBC + 随机 IV", "crypto"))
            if fn.startswith("DES") or "DES3" in fn:
                findings.append(_ev(
                    "crypto.weak_cipher_des", "弱加密算法 (DES)", "high", path, line,
                    f"使用 DES 算法: {fn}", "改用 AES-GCM", "crypto"))
            # fixed IV with literal
            m = _find_kw_literal(call, src, ("iv", "nonce"))
            if m:
                findings.append(_ev(
                    "crypto.fixed_iv", "固定 IV/nonce", "high", path, line,
                    f"加密调用 {fn} 使用固定 IV {m[2]}", "每次加密生成随机 IV 并通过参数传递", "crypto"))
        if fn.endswith(".new") and ("MODE.ECB" in args or "CipherMode.ECB" in args):
            findings.append(_ev(
                "crypto.ecb_mode", "不安全加密模式 (ECB)", "high", path, line,
                f"{fn} 使用 ECB 模式", "改用 GCM/CBC + 随机 IV", "crypto"))

        # ------ hardcoded random seed ------
        if fn in ("random.seed", "np.random.seed", "numpy.random.seed",
                  "torch.manual_seed", "torch.random.manual_seed", "random.seedfn"):
            seed_val = _arg_literal(call, src)
            if seed_val is not None and _is_literal_scalar(seed_val):
                findings.append(_ev(
                    "crypto.hardcoded_seed", "硬编码随机种子", "medium", path, line,
                    f"随机种子被硬编码为 {seed_val}", "改为随机种子 (os.urandom) 或可配置", "crypto"))

        # ------ unsafe deserialization ------
        if fn in ("pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads"):
            findings.append(_ev(
                "deser.pickle", "不安全反序列化 (pickle)", "critical", path, line,
                f"pickle 反序列化 {args}", "改用 JSON / 安全序列化格式", "deserialization"))

        if fn in ("yaml.load", "yaml.full_load_all", "yaml.load_all"):
            if not _yaml_safe(fn, call, src, args):
                findings.append(_ev(
                    "deser.yaml_load", "不安全 yaml.load", "critical", path, line,
                    f"yaml.load 未使用安全 Loader", "改用 yaml.safe_load(data)", "deserialization"))
        if fn == "yaml.unsafe_load" or fn == "yaml.unsafe_load_all":
            findings.append(_ev(
                "deser.yaml_load", "不安全 yaml.load", "critical", path, line,
                "显式调用 yaml.unsafe_load", "改用 yaml.safe_load", "deserialization"))

        if fn == "eval" or fn.endswith("(eval") or fn in ("exec", "compile"):
            if _has_external_input(call, src, args):
                findings.append(_ev(
                    "deser.eval", "eval/exec 外部输入", "critical", path, line,
                    f"{fn} 接收外部输入: {args}", "重构，不使用 eval/exec 解析数据", "deserialization"))

        # ------ injection ------
        if fn.endswith(".execute") or fn in ("cursor.execute", "db.execute", "conn.execute",
                                              "execute", "executemany", "cursor3.execute",
                                              "mysql.cursor.execute"):
            if _contains_sql(args) and _has_concat(args):
                findings.append(_ev(
                    "injection.sql_concat", "SQL 拼接注入", "critical", path, line,
                    f"SQL 通过字符串拼接: {args}", "使用参数化查询 (?, %s)", "injection"))
        if fn in ("os.system",) or fn.startswith("subprocess."):
            if "shell=True" in args or "shell = True" in args:
                if _has_concat(args):
                    findings.append(_ev(
                        "injection.shell_concat", "Shell 拼接注入", "critical", path, line,
                        f"subprocess 开放 shell 且拼接命令: {args}", "传入参数列表, 关闭 shell", "injection"))
            # non-shell but still uses string command with concat -> command injection
            if _has_concat(args) and fn in ("subprocess.call", "subprocess.run", "subprocess.Popen",
                                            "subprocess.check_output", "subprocess.check_call",
                                            "os.system"):
                findings.append(_ev(
                    "injection.shell_concat", "Shell 拼接注入", "critical", path, line,
                    f"命令由字符串拼接构造: {args}", "使用参数列表", "injection"))

        # ------ permissions ------
        if fn == "os.chmod" or "chmod" in fn:
            mode = _last_arg(call, src)
            if _is_0777(mode) or _is_0666(mode):
                findings.append(_ev(
                    "perms.chmod_world_writable", "世界可写 chmod", "high", path, line,
                    f"os.chmod 权限 {mode} 世界可写", "使用 0o600/0o700", "permissions"))
        if "makedirs" in fn or fn == "os.makedirs" or fn == "mkdir" or fn == "os.mkdir":
            mode = _last_arg(call, src)
            if _is_0777(mode):
                findings.append(_ev(
                    "perms.world_writable_dir", "世界可写目录", "high", path, line,
                    f"目录创建权限 {mode} 世界可写", "使用 0o700", "permissions"))


_PY_STATIC_STRING = re.compile(r'^(["\'])(.*?)\1$', re.S)


def _py_static_string(txt: str) -> str | None:
    """Value of a static quoted Python string literal; ``None`` otherwise.

    ``None`` covers identifiers, attribute access (``hashlib.md5``), prefix
    strings (``f"..."``, ``b"..."``) and concatenations -- all either
    unverifiable statically or handled by the regex fallback.
    """
    m = _PY_STATIC_STRING.match(txt.strip())
    return m.group(2) if m else None


def _py_positional_args(call, src):
    """Source texts of the positional (non-keyword) named arguments."""
    args = call.child_by_field_name("arguments")
    if args is None:
        return []
    return [src[a.start_byte:a.end_byte]
            for a in args.named_children
            if a.type not in ("keyword_argument", "keyed_element", "list_splat", "dictionary_splat")]


def _find_kw_literal(call, src, names):
    args = call.child_by_field_name("arguments")
    if args is None:
        return None
    # keyword_argument children
    for a in args.named_children:
        if a.type in ("keyword_argument", "keyed_element"):
            kw = a.child_by_field_name("name")
            val = a.child_by_field_name("value")
            if kw is None or val is None:
                continue
            kwname = src[kw.start_byte:kw.end_byte]
            if kwname in names:
                vtxt = src[val.start_byte:val.end_byte]
                return (vtxt, kw, val)
    return None


def _arg_literal(call, src):
    args = call.child_by_field_name("arguments")
    if args is None:
        return None
    named = args.named_children
    if not named:
        return None
    first = named[0]
    return src[first.start_byte:first.end_byte]


def _is_literal_scalar(txt: str) -> bool:
    t = txt.strip()
    if not t:
        return False
    if t.lower() in {"none", "true", "false"}:
        return False
    if t.startswith(("'", '"', "b'", 'b"')):
        return True
    return t.lstrip("-").isdigit()


def _last_arg(call, src):
    args = call.child_by_field_name("arguments")
    if args is None:
        return ""
    named = args.named_children
    if not named:
        return ""
    last = named[-1]
    return src[last.start_byte:last.end_byte]


def _is_0777(mode: str) -> bool:
    return mode.strip() in {"0o777", "0O777", "0o7777", "777", "0x1ff", "0o666", "0666", "0O666", "666"}


def _is_0666(mode: str) -> bool:
    return mode.strip() in {"0o666", "0O666", "0666", "666"}


def _yaml_safe(fn, call, src, args):
    """True if a Loader=SafeLoader that's safe is present."""
    if "SafeLoader" in args or "FullLoader" not in args and "Loader=yaml." in args:
        return "SafeLoader" in args
    return False


def _contains_sql(args: str) -> bool:
    return any(w in args.upper() for w in ("SELECT ", "INSERT ", "UPDATE ", "DELETE ", "DROP ", "CREATE ",
                                           "SELECT", "INSERT", "UPDATE", "DELETE"))


def _has_fstring_interp(args: str) -> bool:
    """True if ``args`` contains a Python f-string with ``{...}`` interpolation.

    Escaped literal braces (``{{ }}``) do not count as interpolation, so a
    constant f-string is left alone.  The scan is line-narrowed to the f-string
    body via ``re.S`` so embedded quotes/format specs inside the braces do not
    cut the match short.
    """
    for m in re.finditer(r'f(["\'])(.*?)\1', args, re.S):
        body = re.sub(r'\{\{.*?\}\}', "", m.group(2))
        if "{" in body:
            return True
    return False


def _has_concat(args: str) -> bool:
    if " + " in args or "+" in args or "%s" in args and " % " in args:
        return True
    # F-string / template-literal interpolation is the most common SQL
    # injection idiom in AI-generated code (e.g. ``execute(f"...{x}")``).
    if _has_fstring_interp(args):
        return True
    if "`" in args and "${" in args:
        return True
    return False


def _has_external_input(call, src, args) -> bool:
    ext = ("request.", "input(", "sys.argv", "os.environ", ".form[", ".json(", ".body",
           "req.", "ctx.", "kwargs", "data[", "params", "args[")
    low = args.lower()
    return any(x.lower() in low for x in ext)


# --------------------------------------------------------------------------
# JS / TS AST analysis
# --------------------------------------------------------------------------

def analyze_jsts(path, src, findings):
    tree = parse(src, "typescript" if path.endswith((".ts", ".tsx", ".mts", ".cts")) else "javascript")
    root = tree.root_node
    for call in collect_calls(root, src):
        fn = call_fn_name(call, src)
        args = args_text(call, src)
        line = _line_for(call)

        # crypto.createHash('md5') / `sha1` / "md5" and createHmac (any
        # quoted/backtick static first arg carrying the digest algorithm).
        if (fn.endswith(".createHash") or fn == "createHash"
                or fn.endswith(".createHmac") or fn == "createHmac"):
            algo_match = _js_static_string_arg(args)
            if algo_match is not None and algo_match.lower() in ("md5", "sha1"):
                findings.append(_ev(
                    "crypto.md5_or_sha1", "弱哈希算法 (MD5/SHA1)", "high", path, line,
                    f"使用 MD5/SHA1 哈希: {args}", "改用 sha256", "crypto"))

        # Public JS weak-digest libraries carry the algorithm in the function
        # name itself: CryptoJS.SHA1/MD5, forge md5/sha1, bare md5()/sha1()
        # helpers. The regex fallback demands a `Crypto.Hash.` style prefix
        # (CryptoJS is not matched) and is case-sensitive for `sha1`, so these
        # would otherwise slip through.
        if fn.endswith((".MD5", ".SHA1", ".md5", ".sha1")) or fn in ("md5", "sha1"):
            findings.append(_ev(
                "crypto.md5_or_sha1", "弱哈希算法 (MD5/SHA1)", "high", path, line,
                f"使用弱哈希: {fn}()", "改用 sha256 (crypto.createHash)", "crypto"))

        # node crypto cipher with ECB
        if "ECB" in args or "CipherMode.ECB" in args:
            findings.append(_ev(
                "crypto.ecb_mode", "不安全加密模式 (ECB)", "high", path, line,
                f"使用 ECB 加密模式: {fn}({args})", "改用 GCM", "crypto"))

        # DES usage in JS crypto
        if fn in ("des.createCipheriv", "des.createCipher") or "DES" in fn:
            findings.append(_ev(
                "crypto.weak_cipher_des", "弱加密算法 (DES)", "high", path, line,
                f"使用 DES 算法: {fn}", "改用 AES-GCM", "crypto"))

        # hardcoded seed (Math.random / crypto not seedable in JS; skip)

        # unsafe deserialization: eval( on external.  ``Function`` is the
        # constructor twin of eval: ``new Function`` parses as a
        # new_expression (handled on its own pass below), while a plain
        # ``Function(...)`` call or ``window.Function(...)`` lands here.
        if fn == "eval" or fn == "Function" or fn.endswith(".Function"):
            if _js_external(args):
                findings.append(_ev(
                    "deser.eval", "eval 外部输入", "critical", path, line,
                    f"eval/Function 处理外部输入: {args}", "重构，不使用 eval", "deserialization"))

        # JSON.parse with reviver? Not a rule; skip.

        # SQL concat
        if _fn_is_db_query(fn):
            if _contains_sql(args) and _has_concat(args):
                findings.append(_ev(
                    "injection.sql_concat", "SQL 拼接注入", "critical", path, line,
                    f"SQL 通过字符串拼接: {args}", "使用参数化查询 ($1)", "injection"))

        # shell: exec/spawn with shell and concat.  execSync / spawnSync /
        # fork are the synchronous / child forms of the same commands and
        # carry the identical injection surface; ``require('child_process')
        # .execSync(...)`` surfaces as fn ending in ``.execSync``.
        if (fn in ("exec", "execa", "spawn", "execSync", "spawnSync", "fork")
                or fn.endswith(".exec") or fn.endswith(".spawn")
                or fn.endswith(".execSync") or fn.endswith(".spawnSync")
                or fn.endswith(".fork")):
            if "shell" in args.lower() and _has_concat(args):
                findings.append(_ev(
                    "injection.shell_concat", "Shell 拼接注入", "critical", path, line,
                    f"{fn} 开启 shell 并拼接命令: {args}", "使用参数列表", "injection"))
            elif _has_concat(args):
                findings.append(_ev(
                    "injection.shell_concat", "Shell 拼接注入", "critical", path, line,
                    f"命令字符串由拼接构造: {args}", "使用参数列表", "injection"))

        # chmod 0777 (node fs)
        if fn == "fs.chmod" or fn.endswith(".chmod") or fn == "chmodSync":
            mode = _last_arg(call, src)
            m = mode.replace("0o", "").replace("0x", "")
            if mode in ("0o777", "777") or "0o666" in mode:
                findings.append(_ev(
                    "perms.chmod_world_writable", "世界可写 chmod", "high", path, line,
                    f"fs.chmod 权限 {mode} 世界可写", "使用 0o600", "permissions"))
        if "writeFile" in fn or "writeFileSync" in fn:
            args_body = args
            if "/tmp" in args_body:
                findings.append(_ev(
                    "perms.tmp_write_insecure", "不安全 /tmp 写入", "medium", path, line,
                    "直接写 /tmp 易受符号链接攻击", "使用 os.tmpdir()+mkstemp 私有文件", "permissions"))

    # new Function(...) parses as a ``new_expression``, which ``collect_calls``
    # never yields (the dead-code trap that hid this from detection).  Only the
    # Function constructor can execute a string body at runtime, so scan those
    # nodes on their own pass.
    for new_expr in collect_new_expressions(root):
        ctor = new_expression_name(new_expr, src)
        if ctor != "Function":
            continue
        body = args_text(new_expr, src)
        if not _js_external(body):
            continue
        findings.append(_ev(
            "deser.eval", "eval 外部输入", "critical", path, _line_for(new_expr),
            f"new Function 处理外部输入: {body}", "重构，不使用 Function 构造器", "deserialization"))


def _fn_is_db_query(fn: str) -> bool:
    fn = fn.lower()
    return any(k in fn for k in ("db.query", ".query(", ".run(", ".all(", ".get(",
                                 "mysql.query", "pg.query", "knex.raw", "sequelize.query",
                                 "prisma.")) or fn.endswith(".execute")


def _js_external(args: str) -> bool:
    low = args.lower()
    return any(x in low for x in ("req.", "request.", "query.", "body.", "ctx.",
                                  "process.env", "input", "form", "url."))


_JS_STATIC_STRING = re.compile(r"^[`\"']([A-Za-z0-9_.\-]+)[`\"']")


def _js_static_string_arg(args: str) -> str | None:
    """Return the value of a static first string argument of a JS call.

    ``args`` is the raw source text of the ``arguments`` node, which includes
    the wrapping parentheses (``("md5")``). Only a static first literal counts
    -- single-quote, double-quote or backtick -- so ``('sha1', key)`` and
    ``(`md5`)`` are recognised, while identifiers, concatenations and
    interpolated templates return ``None`` (dynamic, unverifiable).
    """
    inner = args.strip()
    if not (inner.startswith("(") and inner.endswith(")")):
        return None
    m = _JS_STATIC_STRING.match(inner[1:-1].strip())
    return m.group(1) if m else None
