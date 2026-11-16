"""Regression tests for JS crypto.createHash weak-hash detection.

Historically only quote-delimited literals matched, so a static template
literal like ``crypto.createHash(`sha1`)`` escaped detection while its
double-quoted sibling did not. These tests pin the accepted static-string
forms (single/double quotes AND backticks) and assert dynamic algorithms
stay quiet (they are unverifiable, not provably safe).
"""

from __future__ import annotations

from cursorscan.scanners.ast import analyze_jsts


def _js(code: str):
    finds = []
    analyze_jsts("x.js", code, finds)
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
        # hash and predates no detection; do not regress it.
        finds = _js('crypto.pbkdf2Sync("x", salt, 10000, 64, "sha1")\n')
        assert finds == []


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
