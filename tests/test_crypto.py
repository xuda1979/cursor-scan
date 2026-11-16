"""Regression tests for JS crypto.createHash weak-hash detection.

Historically only quote-delimited literals matched, so a static template
literal like ``crypto.createHash(`sha1`)`` escaped detection while its
double-quoted sibling did not. These tests pin the accepted static-string
forms (single/double quotes AND backticks) and assert dynamic algorithms
stay quiet (they are unverifiable, not provably safe).
"""

from __future__ import annotations

from cursorscan.scanners.ast import analyze_jsts, analyze_python


def _js(code: str):
    finds = []
    analyze_jsts("x.js", code, finds)
    return finds


def _py(code: str):
    finds = []
    analyze_python("x.py", code, finds)
    return finds


class TestCreateHashStaticArgs:
    def test_double_quoted_md5_flags(self):
        finds = _js('crypto.createHash("md5")\n')
        assert [(f.rule_id, f.line) for f in finds] == \
            [("crypto.md5_or_sha1", 1)]

    def test_single_quoted_sha1_flags(self):
        finds = _js("crypto.createHash('sha1')\n")
        assert [f.rule_id for f in finds] == ["crypto.md5_or_sha1"]

    def test_template_literal_sha1_flags(self):
        # The regression this suite guards: a static backtick literal must
        # count like any other quoted static string.
        finds = _js("crypto.createHash(`sha1`)\n")
        assert [(f.rule_id, f.line) for f in finds] == \
            [("crypto.md5_or_sha1", 1)]

    def test_template_literal_md5_flags(self):
        finds = _js("crypto.createHash(`md5`)\n")
        assert [f.rule_id for f in finds] == ["crypto.md5_or_sha1"]

    def test_flagged_finding_carries_fix(self):
        finds = _js("crypto.createHash(`sha1`)\n")
        assert "sha256" in finds[0].fix
        assert finds[0].dimension == "crypto"
        assert finds[0].severity == "high"


class TestCreateHashSafeAndDynamic:
    def test_sha256_quoted_is_quiet(self):
        finds = _js('crypto.createHash("sha256")\n')
        assert finds == []

    def test_sha512_template_literal_is_quiet(self):
        finds = _js("crypto.createHash(`sha512`)\n")
        assert finds == []

    def test_dynamic_algorithm_is_quiet(self):
        # createHash(userAlgo) reads a runtime value; not provably weak.
        finds = _js("crypto.createHash(userAlgo)\n")
        assert finds == []

    def test_interpolated_template_is_quiet(self):
        finds = _js("crypto.createHash(`${algo}`)\n")
        assert finds == []

    def test_concatenated_argument_is_quiet(self):
        finds = _js('crypto.createHash("sh" + "a1")\n')
        assert finds == []


class TestCreateHmacStaticArgs:
    """createHmac(algorithm, key) shares createHash's weak-digest family; the
    digest is always the first argument."""

    def test_double_quoted_sha1_hmac_flags(self):
        finds = _js('crypto.createHmac("sha1", secret)\n')
        assert [(f.rule_id, f.line) for f in finds] == \
            [("crypto.md5_or_sha1", 1)]

    def test_single_quoted_md5_hmac_flags(self):
        finds = _js("crypto.createHmac('md5', secret)\n")
        assert [f.rule_id for f in finds] == ["crypto.md5_or_sha1"]

    def test_template_literal_sha1_hmac_flags(self):
        finds = _js("crypto.createHmac(`sha1`, secret)\n")
        assert [(f.rule_id, f.line) for f in finds] == \
            [("crypto.md5_or_sha1", 1)]

    def test_hmac_without_dot_namespace_flags(self):
        finds = _js("createHmac('sha1', key)\n")
        assert [f.rule_id for f in finds] == ["crypto.md5_or_sha1"]

    def test_sha256_hmac_is_quiet(self):
        finds = _js("crypto.createHmac('sha256', secret)\n")
        assert finds == []

    def test_dynamic_digest_hmac_is_quiet(self):
        finds = _js("crypto.createHmac(chosenDigest, secret)\n")
        assert finds == []


class TestNamedWeakDigestHelpers:
    """Public JS weak-hash libraries name the algorithm in the call itself:
    CryptoJS.SHA1/MD5, node-forge md5/sha1, and bare md5()/sha1() helpers.
    None of those match the Crypto.Hash-prefixed regex fallback."""

    def test_cryptojs_md5_flags(self):
        finds = _js("const h = CryptoJS.MD5(payload)\n")
        assert [(f.rule_id, f.line) for f in finds] == \
            [("crypto.md5_or_sha1", 1)]

    def test_cryptojs_sha1_flags(self):
        finds = _js("const h = CryptoJS.SHA1(data)\n")
        assert [f.rule_id for f in finds] == ["crypto.md5_or_sha1"]

    def test_bare_md5_flags(self):
        finds = _js("const h = md5(text)\n")
        assert [f.rule_id for f in finds] == ["crypto.md5_or_sha1"]

    def test_bare_sha1_flags(self):
        finds = _js("const h = sha1(input)\n")
        assert [f.rule_id for f in finds] == ["crypto.md5_or_sha1"]

    def test_forge_md5_flags(self):
        finds = _js("const h = forge.md5(data)\n")
        assert [f.rule_id for f in finds] == ["crypto.md5_or_sha1"]

    def test_flagged_finding_carries_metadata(self):
        finds = _js("CryptoJS.MD5(payload)\n")
        assert finds[0].dimension == "crypto"
        assert finds[0].severity == "high"
        assert "sha256" in finds[0].fix

    def test_sha256_family_is_quiet(self):
        finds = _js("const a = CryptoJS.SHA256(x)\n"
                    "const b = CryptoJS.HmacSHA256(secret, msg)\n"
                    "const c = CryptoJS.SHA3(y)\n"
                    "const d = sha256(z)\n")
        assert finds == []

    def test_object_members_named_md5_not_calls_stay_quiet(self):
        # Reading a field like CryptoJS.lib object access is not a weak hash.
        finds = _js("console.log(CryptoJS.lib.WordArray)\n")
        assert finds == []

    def test_pbkdf2_sha1_prf_is_quiet(self):
        # PBKDF2 using SHA-1 as an HMAC PRF is not a collision-prone direct
        # hash and predates no detection; do not regress it.  Iterations stay
        # far above the <100k weak-KDF threshold so only the PRF is exercised.
        finds = _js('crypto.pbkdf2Sync("x", salt, 300000, 64, "sha1")\n')
        assert finds == []


class TestPythonHmacDigestArgs:
    """Python ``hmac.new`` / ``hmac.HMAC`` pass the digest as a plain string
    (``"md5"`` / ``"sha1"``), which the regex fallback (hashlib.* references
    only) does not see. The digest is positional-or-keyword in the same way
    the JS createHmac branch treats its first argument."""

    def test_positional_md5_flags(self):
        finds = _py('import hmac\nhmac.new(key, msg, "md5")\n')
        assert [(f.rule_id, f.line) for f in finds] == \
            [("crypto.md5_or_sha1", 2)]

    def test_positional_single_quoted_sha1_flags(self):
        finds = _py("import hmac\nhmac.new(key, msg, 'sha1')\n")
        assert [f.rule_id for f in finds] == ["crypto.md5_or_sha1"]

    def test_digestmod_keyword_flags(self):
        finds = _py('import hmac\nhmac.new(key=key, msg=msg, digestmod="md5")\n')
        assert [(f.rule_id, f.line) for f in finds] == \
            [("crypto.md5_or_sha1", 2)]

    def test_hmac_class_form_flags(self):
        finds = _py('import hmac\nhmac.HMAC(key, msg, "sha1")\n')
        assert [(f.rule_id, f.line) for f in finds] == \
            [("crypto.md5_or_sha1", 2)]

    def test_keyword_three_positional_order_still_flags(self):
        # Keyword args appear before positional in the argument_list node;
        # only the *third positional* (or the digestmod keyword) is checked.
        finds = _py('import hmac\nhmac.new(key, msg, digestmod="sha1")\n')
        assert [f.rule_id for f in finds] == ["crypto.md5_or_sha1"]

    def test_sha256_digest_quiet(self):
        finds = _py('import hmac\nhmac.new(key, msg, "sha256")\n')
        assert finds == []

    def test_none_digest_quiet(self):
        # The default digest is the library choice; not provably weak.
        finds = _py("import hmac\nhmac.new(key, msg)\n")
        assert finds == []

    def test_dynamic_digest_quiet(self):
        finds = _py("import hmac\nhmac.new(key, msg, digestmod=chosen)\n")
        assert finds == []

    def test_md5_as_key_data_not_digest_quiet(self):
        # The digest is the third positional argument, not the key.
        finds = _py('import hmac\nhmac.new("md5-key", msg, "sha256")\n')
        assert finds == []

    def test_flagged_finding_carries_fix(self):
        finds = _py('import hmac\nhmac.new(key, msg, "md5")\n')
        assert finds[0].dimension == "crypto"
        assert finds[0].severity == "high"
        assert "sha256" in finds[0].fix


class TestJsFixedIv:
    """createCipheriv(alg, key, iv) / createDecipheriv with a static-literal
    IV: the IV is fixed across runs (crypto.fixed_iv)."""

    def test_create_cipheriv_static_iv_flags(self):
        finds = _js('crypto.createCipheriv("aes-256-cbc", key, "0123456789abcdef")\n')
        assert [(f.rule_id, f.severity) for f in finds] == \
            [("crypto.fixed_iv", "high")]

    def test_create_decipheriv_static_iv_flags(self):
        # JS has no b'' byte literals; the static quoted form is what a
        # Buffer.from(iv, 'utf8') call site typically passes.
        finds = _js("crypto.createDecipheriv('aes-256-cbc', key, '0123456789abcdef')\n")
        assert [f.rule_id for f in finds] == ["crypto.fixed_iv"]

    def test_single_quote_buffer_iv_flags(self):
        finds = _js("crypto.createCipheriv('aes-256-cbc', key, 'abcdef')\n")
        assert [f.rule_id for f in finds] == ["crypto.fixed_iv"]

    def test_dynamic_iv_is_quiet(self):
        finds = _js("crypto.createCipheriv('aes-256-cbc', key, crypto.randomBytes(16))\n")
        assert finds == []

    def test_variable_iv_is_quiet(self):
        finds = _js("crypto.createCipheriv('aes-256-cbc', key, iv)\n")
        assert finds == []

    def test_template_literal_iv_is_quiet(self):
        # Backtick templates may carry ${...} interpolation; not provably fixed.
        finds = _js('crypto.createCipheriv(\'aes-256-cbc\', key, `abcdef`)\n')
        assert finds == []


class TestPyFixedIv:
    """Python AES.new(key, mode, iv): the dedicated positional IV argument,
    and the iv=/nonce= keyword form, when the value is a static constant."""

    def test_positional_bytes_iv_flags(self):
        finds = _py('cipher = AES.new(key, AES.MODE_CBC, b"0123456789abcdef")\n')
        assert [(f.rule_id, f.severity) for f in finds] == \
            [("crypto.fixed_iv", "high")]

    def test_positional_str_iv_flags(self):
        finds = _py("cipher = AES.new(key, AES.MODE_CBC, '0123456789abcdef')\n")
        assert [f.rule_id for f in finds] == ["crypto.fixed_iv"]

    def test_keyword_literal_iv_flags(self):
        finds = _py('cipher = AES.new(key, AES.MODE_CBC, iv=b"0123456789abcdef")\n')
        assert [f.rule_id for f in finds] == ["crypto.fixed_iv"]

    def test_keyword_variable_iv_is_quiet(self):
        finds = _py('nonce = secrets.token_bytes(12)\n'
                    'cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)\n')
        assert finds == []

    def test_positional_variable_iv_is_quiet(self):
        finds = _py("cipher = AES.new(key, AES.MODE_CBC, iv_var)\n")
        assert finds == []

    def test_fstring_iv_is_quiet(self):
        finds = _py('cipher = AES.new(key, AES.MODE_CBC, f"{prefix}x")\n')
        assert finds == []


class TestJsWeakKdf:
    """pbkdf2Sync(pw, salt, iterations, keylen, digest): fewer than 100k
    iterations makes brute-forcing cheap."""

    def test_low_iterations_flags(self):
        finds = _js('crypto.pbkdf2Sync(pw, salt, 10000, 64, "sha256")\n')
        assert [(f.rule_id, f.severity) for f in finds] == \
            [("crypto.weak_kdf", "medium")]

    def test_high_iterations_is_quiet(self):
        finds = _js('crypto.pbkdf2Sync(pw, salt, 310000, 64, "sha256")\n')
        assert finds == []

    def test_dynamic_iterations_is_quiet(self):
        finds = _js("crypto.pbkdf2Sync(pw, salt, iters, 64, 'sha256')\n")
        assert finds == []


class TestPyWeakKdf:
    """hashlib.pbkdf2_hmac(hash, password, salt, iterations, ...): iterations
    is the fourth positional argument."""

    def test_low_iterations_flags(self):
        finds = _py('dk = hashlib.pbkdf2_hmac("sha256", pw, salt, 1000)\n')
        assert [(f.rule_id, f.severity) for f in finds] == \
            [("crypto.weak_kdf", "medium")]

    def test_underscore_separated_low_iterations_flags(self):
        finds = _py('dk = hashlib.pbkdf2_hmac("sha256", pw, salt, 10_000)\n')
        assert [f.rule_id for f in finds] == ["crypto.weak_kdf"]

    def test_100k_underscore_is_quiet(self):
        finds = _py('dk = hashlib.pbkdf2_hmac("sha256", pw, salt, 100_000)\n')
        assert finds == []

    def test_high_iterations_is_quiet(self):
        finds = _py('dk = hashlib.pbkdf2_hmac("sha256", pw, salt, 310000)\n')
        assert finds == []

    def test_dynamic_iterations_is_quiet(self):
        finds = _py('dk = hashlib.pbkdf2_hmac("sha256", pw, salt, iterations)\n')
        assert finds == []


class TestNonAsciiByteOffsets:
    """tree-sitter reports byte offsets into the UTF-8 encoding; slicing the
    Python str with them corrupted every span after a non-ASCII character.
    These snippets put a multi-byte character before the vulnerable call."""

    def test_python_em_dash_before_md5_call_still_flags(self):
        code = ('"""App内联摘要 — 必须检出。"""\n'
                "import hashlib\n"
                "h = hashlib.md5(b'x')\n")
        finds = _py(code)
        assert ("crypto.md5_or_sha1", 3) in [(f.rule_id, f.line) for f in finds]

    def test_python_chinese_before_fixed_iv_still_flags(self):
        code = ("# 用户数据加密常量\n"
                'cipher = AES.new(key, AES.MODE_CBC, b"0123456789abcdef")\n')
        finds = _py(code)
        assert ("crypto.fixed_iv", 2) in [(f.rule_id, f.line) for f in finds]

    def test_python_chinese_before_pbkdf2_still_flags(self):
        code = ('# 弱口令哈希\n'
                'dk = hashlib.pbkdf2_hmac("sha256", pw, salt, 1000)\n')
        finds = _py(code)
        assert ("crypto.weak_kdf", 2) in [(f.rule_id, f.line) for f in finds]

    def test_js_em_dash_before_cipheriv_still_flags(self):
        code = ('// Token 加密 — 注意 IV 安全\n'
                "crypto.createCipheriv('aes-256-cbc', key, '0123456789abcdef')\n")
        finds = _js(code)
        assert ("crypto.fixed_iv", 2) in [(f.rule_id, f.line) for f in finds]

    def test_js_chinese_comment_before_createhash_still_flags(self):
        code = ('// 生成摘要用来校验长度\n'
                'crypto.createHash("md5")\n')
        finds = _js(code)
        assert ("crypto.md5_or_sha1", 2) in [(f.rule_id, f.line) for f in finds]


class TestE2EFixtureLock:
    def test_bad_fixture_crypto_rules_still_fire(self, scan_bad_dir):
        from cursorscan.scan import scan_project

        result = scan_project(str(scan_bad_dir))
        # The performance fixture history is unchanged: all 5 planted weak
        # crypto rules must still be found.
        expected = {"crypto.md5_or_sha1", "crypto.weak_cipher_des",
                    "crypto.ecb_mode", "crypto.fixed_iv", "crypto.hardcoded_seed"}
        got = {f.rule_id for f in result.findings}
        assert expected <= got

    def test_good_fixture_stays_crypto_clean(self, scan_good_dir):
        from cursorscan.scan import scan_project

        result = scan_project(str(scan_good_dir))
        assert all(f.dimension != "crypto" for f in result.findings)
