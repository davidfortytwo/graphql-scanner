"""Regression tests: caller credentials must never reach evidence/*.

Defect: build_curl_post/build_curl_get/build_curl_options embed every caller
header (Authorization, Cookie, ...) into the curl string, and report_finding()
persisted that string verbatim to evidence/<finding>.json (payload
"verify_curl") and evidence/<finding>.txt ("verify_curl (bash)" section).

Fails before the fix (secret found in the files); passes after.
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import scan  # noqa: E402

AUTH_VALUE = "Bearer eyJhbGciOiJSUzI1NiJ9.SUPERSECRETVALUE.DO-NOT-LEAK"
COOKIE_VALUE = "JSESSIONID=0123456789ABCDEFDEADBEEF"
APIKEY_VALUE = "AKIAIOSFODNN7EXAMPLEKEY"

SECRETS = (AUTH_VALUE, COOKIE_VALUE, APIKEY_VALUE)


def _stub_verify(monkeypatch, executed):
    """Stub the network curl run; capture exactly what the scanner executes."""

    def _fake(cmd, timeout=scan.CURL_TIMEOUT):
        executed.append(cmd)
        return True, '{"data":{"__schema":{}}}', "", 0

    monkeypatch.setattr(scan, "run_curl_verify", _fake)


def _report(tmp_path, monkeypatch):
    headers = {
        "Authorization": AUTH_VALUE,
        "Cookie": COOKIE_VALUE,
        "X-Api-Key": APIKEY_VALUE,
        "User-Agent": "keep-me-visible/1.0",
    }
    verify = scan.build_curl_post(
        "https://example.test/graphql", headers, {"query": "{ __schema { types { name } } }"}
    )
    executed = []
    _stub_verify(monkeypatch, executed)

    findings = []
    record = scan.report_finding(
        findings,
        "Introspection enabled",
        "LOW",
        evidence_obj={"schema_sample": [{"name": "User"}]},
        raw_text='{"data":{"__schema":{}}}',
        verify_curl=verify,
        verify_markers=["__schema"],
    )
    assert record is not None, "verified finding must still be recorded"
    return executed


def test_authorization_never_reaches_evidence_files(tmp_path, monkeypatch):
    monkeypatch.setattr(scan, "EVIDENCE_DIR", str(tmp_path))
    _report(tmp_path, monkeypatch)

    written = sorted(tmp_path.iterdir())
    assert [p.suffix for p in written] == [".json", ".txt"], written

    for p in written:
        blob = p.read_text(encoding="utf-8")
        for secret in SECRETS:
            assert secret not in blob, f"{secret!r} leaked into {p.name}"
        assert scan.REDACTED in blob, f"no redaction marker in {p.name}"
        # Non-secret context is kept so the operator can still read the report.
        assert "User-Agent: keep-me-visible/1.0" in blob, p.name


def test_executed_curl_still_carries_real_credentials(tmp_path, monkeypatch):
    """Redaction is persistence-only: verification must still authenticate."""
    monkeypatch.setattr(scan, "EVIDENCE_DIR", str(tmp_path))
    executed = _report(tmp_path, monkeypatch)

    assert len(executed) == 1, executed
    assert AUTH_VALUE in executed[0], "scanner would stop reproducing real findings"


def test_redaction_covers_get_and_options_builders():
    headers = {"Authorization": AUTH_VALUE, "X-Request-Id": "keep-me"}
    for cmd in (
        scan.build_curl_get("https://example.test/g", headers, {"q": "1"}),
        scan.build_curl_options("https://example.test/g", headers),
    ):
        red = scan.redact_curl_secrets(cmd)
        assert AUTH_VALUE not in red
        assert scan.REDACTED in red
        assert "X-Request-Id: keep-me" in red


def test_redaction_does_not_break_insecure_optin():
    cmd = scan.build_curl_post(
        "https://example.test/graphql", {"Authorization": AUTH_VALUE}, {"query": "{}"}, insecure=True
    )
    assert "-k" in cmd, "--insecure must still emit -k"
    red = scan.redact_curl_secrets(cmd)
    assert "-k" in red
    assert AUTH_VALUE not in red


def test_redaction_preserves_shell_quoting_mitigation():
    """sh_quote escapes single quotes; redaction must not undo that."""
    cmd = scan.build_curl_post(
        "https://example.test/graphql",
        {"Authorization": AUTH_VALUE, "X-Note": "it's-fine"},
        {"query": "{}"},
    )
    assert """X-Note: it'"'"'s-fine'""" in cmd
    red = scan.redact_curl_secrets(cmd)
    assert """X-Note: it'"'"'s-fine'""" in red
    assert AUTH_VALUE not in red


def test_non_string_input_is_tolerated():
    assert scan.redact_curl_secrets("") == ""
    assert scan.redact_curl_secrets(None) is None