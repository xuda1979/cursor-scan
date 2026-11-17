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


def _bstr(bsrc: bytes, start: int, end: int) -> str:
    """Slice a node's source span and decode back to text.

    tree-sitter parses ``source.encode("utf-8")``, so ``start_byte`` /
    ``end_byte`` are UTF-8 byte offsets into the encoded source.  Slicing the
    original ``str`` with those offsets corrupts every span after the first
    non-ASCII character, so spans are taken from the encoded bytes and decoded.
    """
    return bsrc[start:end].decode("utf-8", errors="surrogatepass")


def new_expression_name(node, bsrc: bytes) -> str:
    """Textual constructor name of a ``new_expression``, e.g. ``Function``."""
    ctor = node.child_by_field_name("constructor")
    if ctor is None:
        return ""
    return _bstr(bsrc, ctor.start_byte, ctor.end_byte)


def call_fn_name(node, bsrc: bytes) -> str:
    """Return textual form of call function, e.g. 'hashlib.md5', 'yaml.load'."""
    fn = node.child_by_field_name("function")
    if fn is None:
        return ""
    return _bstr(bsrc, fn.start_byte, fn.end_byte)


def args_text(node, bsrc: bytes) -> str:
    args = node.child_by_field_name("arguments")
    if args is None:
        return ""
    return _bstr(bsrc, args.start_byte, args.end_byte)


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
    bsrc = src.encode("utf-8", errors="surrogatepass")
    for call in collect_calls(root, src):
        fn = call_fn_name(call, bsrc)
        args = args_text(call, bsrc)
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
            kw = _find_kw_literal(call, bsrc, ("digestmod",))
            if kw is not None:
                digest = _py_static_string(kw[0])  # digestmod="md5"
            else:
                pos = _py_positional_args(call, bsrc)
                if len(pos) >= 3:
                    digest = _py_static_string(pos[2])  # hmac.new(key, msg, "md5")
            if digest is not None and digest.lower() in ("md5", "sha1"):
                findings.append(_ev(
                    "crypto.md5_or_sha1", "弱哈希算法 (MD5/SHA1)", "high", path, line,
                    f"HMAC 使用弱摘要 {digest}: {fn}({args})", "改用 sha256 摘要", "crypto"))

        # weak KDF: too few PBKDF2 iterations (< 100k) makes brute forcing
        # cheap.  hashlib.pbkdf2_hmac(hash, password, salt, iterations, ...):
        # iterations is the fourth positional argument.
        if fn == "hashlib.pbkdf2_hmac":
            pos = _py_positional_args(call, bsrc)
            if len(pos) >= 4 and _py_static_int(pos[3]) is not None \
                    and _py_static_int(pos[3]) < 100000:
                findings.append(_ev(
                    "crypto.weak_kdf", "弱密钥派生 (KDF 迭代过少)", "medium", path, line,
                    f"PBKDF2 迭代次数过少: {pos[3].strip()}", "使用 >= 100000 次迭代 (如 310000)", "crypto"))

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
            # fixed IV with a literal value only: ``iv=iv`` / ``nonce=nonce``
            # pass a runtime variable, so only static constants prove the IV is
            # fixed across runs.
            m = _find_kw_literal(call, bsrc, ("iv", "nonce"))
            if m and _py_static_value(m[0]) is not None:
                findings.append(_ev(
                    "crypto.fixed_iv", "固定 IV/nonce", "high", path, line,
                    f"加密调用 {fn} 使用固定 IV {m[2]}", "每次加密生成随机 IV 并通过参数传递", "crypto"))
            # positional form: AES.new(key, mode, iv) -- the dedicated
            # positional IV argument, e.g. AES.new(key, AES.MODE_CBC, b'...').
            pos = _py_positional_args(call, bsrc)
            if len(pos) >= 3 and _py_static_value(pos[2]) is not None:
                findings.append(_ev(
                    "crypto.fixed_iv", "固定 IV/nonce", "high", path, line,
                    f"加密调用 {fn} 使用固定 IV {pos[2].strip()}", "每次加密生成随机 IV 并通过参数传递", "crypto"))
        if fn.endswith(".new") and ("MODE.ECB" in args or "CipherMode.ECB" in args):
            findings.append(_ev(
                "crypto.ecb_mode", "不安全加密模式 (ECB)", "high", path, line,
                f"{fn} 使用 ECB 模式", "改用 GCM/CBC + 随机 IV", "crypto"))

        # ------ hardcoded random seed ------
        if fn in ("random.seed", "np.random.seed", "numpy.random.seed",
                  "torch.manual_seed", "torch.random.manual_seed", "random.seedfn"):
            seed_val = _arg_literal(call, bsrc)
            if seed_val is not None and _is_literal_scalar(seed_val):
                findings.append(_ev(
                    "crypto.hardcoded_seed", "硬编码随机种子", "medium", path, line,
                    f"随机种子被硬编码为 {seed_val}", "改为随机种子 (os.urandom) 或可配置", "crypto"))

        # ------ unsafe deserialization ------
        if fn in ("pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads",
                  "_pickle.load", "_pickle.loads"):
            findings.append(_ev(
                "deser.pickle", "不安全反序列化 (pickle)", "critical", path, line,
                f"pickle 反序列化 {args}", "改用 JSON / 安全序列化格式", "deserialization"))

        # pickle-backed loaders from the ML/data stack execute arbitrary code
        # on load (numpy.load only when allow_pickle=True; torch.load is gated
        # by its weights_only=False default), reusing the deser.pickle rule.
        if fn in ("joblib.load", "pandas.read_pickle", "pd.read_pickle"):
            findings.append(_ev(
                "deser.pickle", "不安全反序列化 (pickle)", "critical", path, line,
                f"{fn} 底层 pickle 反序列化 {args}", "改用安全序列化格式", "deserialization"))
        if fn in ("numpy.load", "np.load") and "allow_pickle=True" in args:
            findings.append(_ev(
                "deser.pickle", "不安全反序列化 (pickle)", "critical", path, line,
                f"np.load 开启 allow_pickle 可执行任意代码", "关闭 allow_pickle 或改用 np.savez", "deserialization"))
        if fn == "torch.load":
            if not _torch_safe(args):
                findings.append(_ev(
                    "deser.pickle", "不安全反序列化 (pickle)", "critical", path, line,
                    f"torch.load 默认 pickle 反序列化 {args}", "使用 weights_only=True 或改用安全格式", "deserialization"))

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
        if fn in ("os.system", "os.popen") or fn.startswith("subprocess."):
            # Which slot the concat lands in decides whether a shell is
            # involved: an explicit shell=True always interprets its command
            # through a shell, and a *string* command (os.system / os.popen /
            # subprocess with a single string argument) is parsed by a shell
            # too.  `sh -c`/`bash -c` handed as the argv list also reaches a
            # shell.  But a concat buried in the *argv list* of a shell-less
            # subprocess call is passed as separate arguments (no metachar
            # expansion), so it must not fire shell injection -- only
            # shell-involved or concat-built command strings.
            if "shell=True" in args or "shell = True" in args:
                if _has_concat(args):
                    findings.append(_ev(
                        "injection.shell_concat", "Shell 拼接注入", "critical", path, line,
                        f"subprocess 开放 shell 且拼接命令: {args}", "传入参数列表, 关闭 shell", "injection"))
            elif fn in ("subprocess.call", "subprocess.run", "subprocess.Popen",
                        "subprocess.check_output", "subprocess.check_call",
                        "os.system", "os.popen"):
                first = _first_positional(call, bsrc)
                cmd = first[0] if first is not None else ""
                arg_list = _first_arg_is_list(call, bsrc)
                if not arg_list and _has_concat(cmd):
                    findings.append(_ev(
                        "injection.shell_concat", "Shell 拼接注入", "critical", path, line,
                        f"命令由字符串拼接构造: {args}", "使用参数列表", "injection"))
                elif arg_list and _SHELL_BIN.search(cmd) is not None \
                        and _SHELL_DASH_C.search(args) is not None \
                        and _has_concat(args):
                    # argv list ``["sh", "-c", "ls " + d]`` -- the command
                    # line is built by concat and then shell-interpreted.
                    findings.append(_ev(
                        "injection.shell_concat", "Shell 拼接注入", "critical", path, line,
                        f"sh -c 命令由字符串拼接构造: {args}", "使用参数列表", "injection"))

        # ------ permissions ------
        if fn == "os.chmod" or "chmod" in fn:
            mode = _last_arg(call, bsrc)
            if _is_0777(mode) or _is_0666(mode):
                findings.append(_ev(
                    "perms.chmod_world_writable", "世界可写 chmod", "high", path, line,
                    f"os.chmod 权限 {mode} 世界可写", "使用 0o600/0o700", "permissions"))
        if "makedirs" in fn or fn == "os.makedirs" or fn == "mkdir" or fn == "os.mkdir":
            mode = _last_arg(call, bsrc)
            if _is_0777(mode):
                findings.append(_ev(
                    "perms.world_writable_dir", "世界可写目录", "high", path, line,
                    f"目录创建权限 {mode} 世界可写", "使用 0o700", "permissions"))


_PY_STATIC_STRING = re.compile(r'^([bfrBF]{0,2})(["\'])(.*?)\2$', re.S)


def _py_static_string(txt: str) -> str | None:
    """Value of a static quoted Python string literal; ``None`` otherwise.

    Identifiers, attribute access (``hashlib.md5``), prefixed strings
    (``f"..."``, ``b"..."``) and concatenations are treated as None, either
    because they are unverifiable statically (dynamic f-strings / bytes hold
    runtime bytes) or because they are handled by the regex fallback.  Callers
    that need raw bytes/pickle literals (a fixed IV is a raw byte constant)
    pass ``allow_prefix=True``.
    """
    m = _PY_STATIC_STRING.match(txt.strip())
    if not m:
        return None
    if m.group(1):
        return None
    return m.group(3)


def _py_static_value(txt: str) -> str | None:
    """Value of a static string literal, allowing bytes/raw prefix.

    Unlike ``_py_static_string``, accepts ``b'...'`` (and other byte prefixes)
    and returns the decoded literal value, so raw IV constants compare as
    ``b'0123456789abcdef'``.  f-strings (any prefix carrying ``f``) are
    rejected: their ``{...}`` interpolation makes them dynamic.
    """
    m = _PY_STATIC_STRING.match(txt.strip())
    if not m:
        return None
    if "f" in m.group(1).lower():
        return None
    return m.group(3)


def _py_positional_args(call, bsrc):
    """Source texts of the positional (non-keyword) named arguments."""
    args = call.child_by_field_name("arguments")
    if args is None:
        return []
    return [_bstr(bsrc, a.start_byte, a.end_byte)
            for a in args.named_children
            if a.type not in ("keyword_argument", "keyed_element", "list_splat", "dictionary_splat")]


def _find_kw_literal(call, bsrc, names):
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
            kwname = _bstr(bsrc, kw.start_byte, kw.end_byte)
            if kwname in names:
                vtxt = _bstr(bsrc, val.start_byte, val.end_byte)
                return (vtxt, kw, val)
    return None


def _arg_literal(call, bsrc):
    args = call.child_by_field_name("arguments")
    if args is None:
        return None
    named = args.named_children
    if not named:
        return None
    first = named[0]
    return _bstr(bsrc, first.start_byte, first.end_byte)


def _is_literal_scalar(txt: str) -> bool:
    t = txt.strip()
    if not t:
        return False
    if t.lower() in {"none", "true", "false"}:
        return False
    if t.startswith(("'", '"', "b'", 'b"')):
        return True
    return t.lstrip("-").isdigit()


def _last_arg(call, bsrc):
    args = call.child_by_field_name("arguments")
    if args is None:
        return ""
    named = args.named_children
    if not named:
        return ""
    last = named[-1]
    return _bstr(bsrc, last.start_byte, last.end_byte)


def _is_0777(mode: str) -> bool:
    return mode.strip() in {"0o777", "0O777", "0o7777", "777", "0x1ff", "0o666", "0666", "0O666", "666"}


def _is_0666(mode: str) -> bool:
    return mode.strip() in {"0o666", "0O666", "0666", "666"}


def _yaml_safe(fn, call, src, args):
    """True if a Loader=SafeLoader that's safe is present."""
    if "SafeLoader" in args or "FullLoader" not in args and "Loader=yaml." in args:
        return "SafeLoader" in args
    return False


def _torch_safe(args: str) -> bool:
    """True when a torch.load call is provably safe: a static
    ``weights_only=True`` keyword.  torch.load historically defaults to the
    unsafe pickle-backed weights_only=False, so an omitted or negative
    weights_only is not forgivable; a dynamic value is unverifiable."""
    m = re.search(r"\bweights_only\s*=\s*True\s*\b", args)
    return m is not None


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
    bsrc = src.encode("utf-8", errors="surrogatepass")
    for call in collect_calls(root, src):
        fn = call_fn_name(call, bsrc)
        args = args_text(call, bsrc)
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

        # node crypto cipher: positional literal IV.  createCipheriv(alg, key,
        # iv) / createDecipheriv(alg, key, iv) -- an IV that is a static string
        # in source is fixed across runs.
        if fn.endswith((".createCipheriv", ".createDecipheriv")) \
                or fn in ("createCipheriv", "createDecipheriv"):
            cargs = _js_positional_args(call, bsrc)
            if len(cargs) >= 3 and _js_plain_string(cargs[2]) is not None:
                findings.append(_ev(
                    "crypto.fixed_iv", "固定 IV/nonce", "high", path, line,
                    f"加密调用 {fn} 使用固定 IV {cargs[2].strip()}", "每次加密生成随机 IV (crypto.randomBytes)", "crypto"))

        # weak KDF: too few PBKDF2 iterations (< 100k) makes brute forcing
        # cheap. Both sync and async node crypto forms put iterations third;
        # Python's hashlib.pbkdf2_hmac puts it fourth.
        if fn.endswith(".pbkdf2Sync") or fn in ("pbkdf2Sync",):
            cargs = _js_positional_args(call, bsrc)
            if len(cargs) >= 3 and _py_static_int(cargs[2]) is not None \
                    and _py_static_int(cargs[2]) < 100000:
                findings.append(_ev(
                    "crypto.weak_kdf", "弱密钥派生 (KDF 迭代过少)", "medium", path, line,
                    f"PBKDF2 迭代次数过少: {cargs[2].strip()}", "使用 >= 100000 次迭代 (如 310000)", "crypto"))
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

        # string-code timers: setTimeout/setInterval/setImmediate convert a
        # non-function first argument to a string and evaluate it as source
        # (CWE-95) -- the async twin of ``eval``.  A concat-built or
        # externally-sourced code string is the same injection surface, while
        # a function callback or a static literal is not provably dynamic.
        if fn in ("setTimeout", "setInterval", "setImmediate") \
                or fn.endswith((".setTimeout", ".setInterval", ".setImmediate")):
            first = _first_positional(call, bsrc)
            if first is not None:
                code, ntype = first
                if ntype not in ("arrow_function", "function", "function_expression"):
                    if "+" in code or "${" in code or _js_external(code):
                        findings.append(_ev(
                            "deser.eval", "eval 等价 (字符串定时器)", "critical", path, line,
                            f"{fn} 以动态字符串为代码: {code}",
                            "改为函数回调，勿拼接代码字符串", "deserialization"))

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
        #
        # Which slot the concat lands in decides whether a shell is involved:
        # exec/execSync always interpret their string command in a shell,
        # while spawn/spawnSync/fork/execa only do so with shell:true or an
        # explicit ``sh -c`` style command line.  A concat buried in the
        # *argument array* of a plain spawn reaches the child as a separate
        # argv entry (no metacharacter expansion), so it must not fire shell
        # injection -- only shell-involved or concat-built command strings.
        if (fn in ("exec", "execa", "spawn", "execSync", "spawnSync", "fork")
                or fn.endswith(".exec") or fn.endswith(".spawn")
                or fn.endswith(".execSync") or fn.endswith(".spawnSync")
                or fn.endswith(".fork")):
            first = _first_positional(call, bsrc)
            cmd = first[0] if first is not None else ""
            cmd_dynamic = _has_concat(cmd)
            sh_dash_c = _SHELL_BIN.search(cmd) is not None \
                and _SHELL_DASH_C.search(args) is not None \
                and _has_concat(args)
            if "shell" in args.lower() and _has_concat(args):
                findings.append(_ev(
                    "injection.shell_concat", "Shell 拼接注入", "critical", path, line,
                    f"{fn} 开启 shell 并拼接命令: {args}", "使用参数列表", "injection"))
            elif cmd_dynamic or sh_dash_c:
                findings.append(_ev(
                    "injection.shell_concat", "Shell 拼接注入", "critical", path, line,
                    f"命令字符串由拼接构造: {args}", "使用参数列表", "injection"))

        # chmod 0777 (node fs)
        if fn == "fs.chmod" or fn.endswith(".chmod") or fn == "chmodSync":
            mode = _last_arg(call, bsrc)
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
        ctor = new_expression_name(new_expr, bsrc)
        if ctor != "Function":
            continue
        body = args_text(new_expr, bsrc)
        if not _js_external(body):
            continue
        findings.append(_ev(
            "deser.eval", "eval 外部输入", "critical", path, _line_for(new_expr),
            f"new Function 处理外部输入: {body}", "重构，不使用 Function 构造器", "deserialization"))


# --- shared static-literal/int helpers --------------------------------------

def _py_static_int(txt: str) -> int | None:
    """Value of a static Python integer literal; ``None`` otherwise.

    Accepts plain digits and Python numeric separators (``100_000``); rejects
    identifiers, arithmetic expressions and any dotted/negative junk so a
    dynamic iteration count never flags.
    """
    t = txt.strip().replace("_", "")
    if t.isdigit():
        return int(t)
    return None


def _js_positional_args(call, bsrc):
    """Source texts of the positional (non-keyword) JS/TS arguments.

    JS has no keyword arguments; this simply skips the comment nodes that
    tree-sitter keeps as named children of ``arguments``.
    """
    args = call.child_by_field_name("arguments")
    if args is None:
        return []
    return [_bstr(bsrc, a.start_byte, a.end_byte)
            for a in args.named_children
            if a.type not in ("comment",)]


_JS_PLAIN_STRING = re.compile(r"^(['\"])(.*?)\1$", re.S)

# Shell-interpreting binaries handed to subprocess/spawn-style calls.  ``bash
# -c`` / ``sh -c`` make the call execute a command line through a shell even
# though it carries no ``shell:``/``shell=True`` option (both the JS spawn
# family and the Python subprocess family).
_SHELL_BIN = re.compile(r"(?i)\b(sh|bash|zsh|dash)\b")
_SHELL_DASH_C = re.compile(r"-c\b")


def _first_positional(call, bsrc):
    """``(source_text, tree_sitter_type)`` of the first positional argument,
    or ``None`` for a call with no arguments.  Node type discriminates the
    string-code timer forms: ``arrow_function``/``function`` callbacks are
    safe, while a RHS whose type is not a function *and* whose text contains
    concat/interpolation/external markers is a dynamic code string.
    """
    args = call.child_by_field_name("arguments")
    if args is None:
        return None
    named = [a for a in args.named_children if a.type != "comment"]
    if not named:
        return None
    return _bstr(bsrc, named[0].start_byte, named[0].end_byte), named[0].type


def _first_arg_is_list(call, bsrc) -> bool:
    """True when the first positional argument is a list literal (the argv
    form of subprocess / spawn).  Python parses ``["ls", d]`` with node type
    ``list``; JS/TS parse array literals as ``array``."""
    first = _first_positional(call, bsrc)
    return first is not None and first[1] in ("list", "array")


def _js_plain_string(txt: str) -> str | None:
    """Value of a static single/double-quoted JS string literal; ``None`` otherwise.

    Backtick templates and identifiers are rejected: templates with ``${...}``
    are dynamic, and an identifier's value is unknowable statically.  Used for
    the positional IV argument of ``createCipheriv`` where only a plain quoted
    constant proves the IV is fixed.
    """
    m = _JS_PLAIN_STRING.match(txt.strip())
    return m.group(2) if m else None


def _fn_is_db_query(fn: str) -> bool:
    fn = fn.lower()
    return any(k in fn for k in ("db.query", ".query(", ".run(", ".all(", ".get(",
                                 "mysql.query", "pg.query", "knex.raw", "sequelize.query",
                                 "prisma.")) or fn.endswith(".execute")


def _js_external(args: str) -> bool:
    """Heuristic: does this JS snippet draw on external input?

    Conservative by design -- static string literals stay quiet and a bare
    identifier is ambiguous, so only named external sources count.  Both
    server-side request plumbing (req./request./body./ctx./process.env...) and
    browser DOM-XSS sources (location./window.name/document.cookie/navigator.
    userAgent/localStorage, the browser twin of request data) drive the
    eval-family rules: a code string built from any of them is
    attacker-influenceable.
    """
    low = args.lower()
    return any(x in low for x in ("req.", "request.", "query.", "body.", "ctx.",
                                  "process.env", "input", "form", "url.",
                                  # browser DOM sources (OWASP DOM XSS)
                                  "location.", "window.name", "document.cookie",
                                  "document.url", "document.referrer",
                                  "useragent", "localstorage", "sessionstorage"))


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
