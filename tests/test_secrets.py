"""Unit tests for the hardcoded-secret rules, incl. AWS secret access keys.

A bare 40-char base64-ish value is ambiguous (hashes, signatures, opaque
tokens), so ``secrets.aws_secret_key`` only fires when the value sits next to
explicit AWS secret context.  The negative cases below lock that in.
"""

from __future__ import annotations

from cursorscan.rules.secrets import analyze_code


def _rules(code: str):
    return [(f.rule_id, f.line) for f in analyze_code("x.py", code)]


SKEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


class TestAwsSecretKeyPositive:
    def test_aws_secret_access_key_assignment(self):
        assert ("secrets.aws_secret_key", 1) in _rules(
            f'aws_secret_access_key = "{SKEY}"\n')

    def test_dict_keyword_form(self):
        assert ("secrets.aws_secret_key", 1) in _rules(
            'secrets = {"aws_secret_access_key": "%s"}\n' % SKEY)

    def test_paired_with_access_key_id(self):
        # Access key ID on the same line supplies the AWS context even when
        # the variable name does not.
        assert ("secrets.aws_secret_key", 1) in _rules(
            'ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE1234"; secret = "%s"\n' % SKEY)


class TestAwsSecretKeyNegative:
    def test_bare_40_char_value_is_not_flagged(self):
        assert "secrets.aws_secret_key" not in {r for r, _ in _rules(
            'token = "%s"\n' % SKEY)}

    def test_short_value_is_not_flagged(self):
        assert "secrets.aws_secret_key" not in {r for r, _ in _rules(
            'aws_secret_access_key = "AbCdEfGhIjK"\n')}

    def test_placeholder_key_is_ignored(self):
        assert "secrets.aws_secret_key" not in {r for r, _ in _rules(
            'aws_secret_access_key = "your-secret-key"\n')}

    def test_utility_value_without_aws_context_is_clean(self):
        # Generic hardcoded_key may still fire for STRONG_HINT_KEYS names;
        # the AWS-specific rule must not.
        rules = _rules('cache_token = "%s"\n' % SKEY)
        assert "secrets.aws_secret_key" not in {r for r, _ in rules}
