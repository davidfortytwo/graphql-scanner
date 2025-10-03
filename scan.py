#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: David Espejo (Fortytwo Security)
# GraphQL checks — evidence JSON only (severity-prefixed) + robust verify_curl (here-doc for POST)
#
# Requirements:
#   pip install requests termcolor
#
# Usage:
#   python3 scan.py -t https://target/graphql -H "Authorization: Bearer XXX"
#   python3 scan.py -t https://target/graphql --json

import argparse
import json
import time
import re
import os
import requests
from urllib.parse import urlencode

try:
    from termcolor import colored
except Exception:
    def colored(s, *_args, **_kwargs):
        return s

DEFAULT_TIMEOUT = 12
EVIDENCE_DIR = "evidence"
VALID_SEVERITIES_FOR_FILES = {"LOW", "MEDIUM", "HIGH"}
SEVERITY_ORDER_PREFIX = {"HIGH": "1-HIGH", "MEDIUM": "2-MEDIUM", "LOW": "3-LOW"}

# ---------------------------
# Helpers: shell quoting, files & HTTP
# ---------------------------

def sh_quote(s: str) -> str:
    """POSIX-safe single-quote for shell."""
    return "'" + (s.replace("'", "'\"'\"'")) + "'"


def ensure_evidence_dir():
    if not os.path.exists(EVIDENCE_DIR):
        os.makedirs(EVIDENCE_DIR, exist_ok=True)


def slugify(name):
    s = re.sub(r'[^a-zA-Z0-9\-_\.]', '-', name).strip('-').lower()
    return s or "finding"


def _basename_for(name, idx, severity):
    sev_prefix = SEVERITY_ORDER_PREFIX.get(severity, f"9-{severity}")
    return f"{sev_prefix}-{slugify(name)}-{idx}"


def write_evidence_json(name, idx, severity, payload):
    """
    Write one JSON evidence file with severity prefix so directory sort groups by severity.
    Filename: "<rank-severity>-<slug>-<idx>.json"
    """
    ensure_evidence_dir()
    base = _basename_for(name, idx, severity) + ".json"
    jpath = os.path.join(EVIDENCE_DIR, base)
    with open(jpath, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False, default=str)
    return jpath


def write_evidence_txt(name, idx, severity, payload):
    """Create a human-readable .txt sibling with the same base name as the JSON."""
    ensure_evidence_dir()
    base = _basename_for(name, idx, severity) + ".txt"
    tpath = os.path.join(EVIDENCE_DIR, base)

    def _section(title):
        return f"\n{'='*8} {title} {'='*8}\n"

    lines = []
    lines.append(f"Finding: {name}")
    lines.append(f"Severity: {severity}")
    ts = payload.get("timestamp")
    if ts:
        lines.append(f"Timestamp: {ts}")

    meta = payload.get("meta")
    if meta:
        lines.append(_section("Meta"))
        lines.append(json.dumps(meta, indent=2, ensure_ascii=False))

    frag = payload.get("fragment")
    if frag:
        lines.append(_section("Fragment"))
        lines.append(str(frag))

    ev = payload.get("evidence")
    if ev is not None:
        lines.append(_section("Evidence"))
        try:
            lines.append(json.dumps(ev, indent=2, ensure_ascii=False))
        except Exception:
            lines.append(str(ev))

    raw = payload.get("raw")
    if raw:
        lines.append(_section("Raw"))
        try:
            # Pretty if JSON-like
            raw_json = json.loads(raw)
            lines.append(json.dumps(raw_json, indent=2, ensure_ascii=False))
        except Exception:
            lines.append(str(raw))

    vc = payload.get("verify_curl", "").strip()
    if vc:
        lines.append(_section("verify_curl (bash) — copy/paste"))
        lines.append(vc)

    with open(tpath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines).rstrip() + "\n")
    return tpath


def _is_json_ct(ct: str) -> bool:
    if not ct:
        return False
    ct = ct.lower()
    return ("application/json" in ct) or ("graphql-response+json" in ct) or ("+json" in ct)


def post_json(url, payload, headers, timeout, verify_tls):
    base = {
        "Content-Type": "application/json",
        "Accept": "application/graphql-response+json, application/json;q=0.9, */*+json;q=0.8",
        "User-Agent": "gql-scanner/1.5 (+https://fortytwo.security)"
    }
    hdrs = {**base, **(headers or {})}
    try:
        t0 = time.time()
        r = requests.post(url, json=payload, headers=hdrs, timeout=timeout, verify=verify_tls)
        elapsed = time.time() - t0
        ct = r.headers.get("Content-Type", "")
        data = None
        if _is_json_ct(ct):
            try:
                data = r.json()
            except ValueError:
                data = None
        return r.status_code, r.headers, data, r.text, elapsed
    except requests.exceptions.RequestException as e:
        return None, {}, None, str(e), None


def get_json(url, params, headers, timeout, verify_tls):
    base = {
        "Accept": "application/graphql-response+json, application/json;q=0.9, */*+json;q=0.8",
        "User-Agent": "gql-scanner/1.5 (+https://fortytwo.security)"
    }
    hdrs = {**base, **(headers or {})}
    try:
        t0 = time.time()
        r = requests.get(url, params=params, headers=hdrs, timeout=timeout, verify=verify_tls)
        elapsed = time.time() - t0
        ct = r.headers.get("Content-Type", "")
        data = None
        if _is_json_ct(ct):
            try:
                data = r.json()
            except ValueError:
                data = None
        return r.status_code, r.headers, data, r.text, elapsed, r.url
    except requests.exceptions.RequestException as e:
        return None, {}, None, str(e), None, None

# ---------------------------
# Curl builders (used in evidence files)
# ---------------------------

def build_curl_post(url, headers, payload, insecure=False):
    """
    Build a copy/paste-safe curl using a here-doc for the JSON body.
    Works cleanly in bash/zsh and avoids quoting/escape pitfalls.
    This returns a *clean* command (no JSON with \n escapes).
    """
    lines = []
    lines.append(f"curl -sS -X POST {sh_quote(url)} \\")
    if insecure:
        lines.append("  -k \\")
    lines.append("  -H 'Content-Type: application/json' \\")
    lines.append("  -H 'Accept: application/graphql-response+json, application/json' \\")
    for k, v in (headers or {}).items():
        lines.append(f"  -H {sh_quote(f'{k}: {v}')} \\")
    lines.append("  --data-binary @- <<'JSON'")
    body = json.dumps(payload, indent=2, ensure_ascii=False)
    lines.append(body)
    lines.append("JSON")
    return "\n".join(lines)


def build_curl_get(url, headers, params, insecure=False):
    qs = urlencode(params or {})
    full = f"{url}?{qs}" if qs else url
    parts = [f"curl -sS -X GET {sh_quote(full)}"]
    if insecure:
        parts.append("-k")
    parts.append("-H 'Accept: application/graphql-response+json, application/json'")
    for k, v in (headers or {}).items():
        parts.append(f"-H {sh_quote(f'{k}: {v}')}")
    return " \\\n  " + " \\\n  ".join(parts)


def build_curl_options(url, headers, insecure=False):
    parts = [f"curl -i -sS -X OPTIONS {sh_quote(url)}"]
    if insecure:
        parts.append("-k")
    parts.append("-H 'Origin: https://example.com'")
    parts.append("-H 'Access-Control-Request-Method: POST'")
    parts.append("-H 'Access-Control-Request-Headers: content-type'")
    for k, v in (headers or {}).items():
        parts.append(f"-H {sh_quote(f'{k}: {v}')}")
    return " \\\n  " + " \\\n  ".join(parts)

# ---------------------------
# Utility printing & parsing
# ---------------------------

def parse_headers(header_list):
    headers = {}
    if not header_list:
        return headers
    for h in header_list:
        if ":" not in h:
            print(colored(f"[!] Ignoring malformed header: {h}", "yellow"))
            continue
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    return headers


def print_result(ok, msg):
    if ok:
        print(colored(f"[+] {msg}", "green"))
    else:
        print(colored(f"[!] {msg}", "red"))


def sev(tag):
    colors = {"LOW":"blue","MEDIUM":"yellow","HIGH":"red","INFO":"cyan"}
    return lambda s: colored(f"{tag}: {s}", colors.get(tag, "white"))


def looks_stacktrace(errors):
    try:
        for e in errors or []:
            ext = e.get("extensions") or {}
            st = ext.get("exception", {}).get("stacktrace") \
                 or ext.get("stacktrace") \
                 or ext.get("debug") \
                 or ext.get("originalError", {}).get("stack")
            if st:
                return True, st
            msg = e.get("message","")
            if "Traceback" in msg or (" at " in msg and ("Exception" in msg or "Error" in msg)):
                return True, msg
    except Exception:
        pass
    return False, None

# ---------------------------
# Evidence helper
# ---------------------------

def extract_fragment_from_evidence(evidence):
    """Short, decisive snippet for copy/paste into reports."""
    if not evidence:
        return ""
    if isinstance(evidence, dict):
        # 1) GraphQL errors
        errors = evidence.get("errors") or evidence.get("data", {}).get("errors")
        if errors and isinstance(errors, list):
            msgs = []
            for e in errors[:5]:
                msg = e.get("message") if isinstance(e, dict) else str(e)
                if msg:
                    msgs.append(msg)
            if msgs:
                return "\n".join(msgs)
        # 2) Stack trace
        def find_stack(obj):
            if isinstance(obj, dict):
                for _, v in obj.items():
                    if isinstance(v, str) and ("Traceback" in v or (" at " in v and ("Exception" in v or "Error" in v))):
                        return v
                    found = find_stack(v)
                    if found:
                        return found
            elif isinstance(obj, list):
                for item in obj:
                    found = find_stack(item)
                    if found:
                        return found
            return None
        st = find_stack(evidence)
        if st:
            return st[:4000] + ("\n...[truncated]" if len(st) > 4000 else "")
        # 3) Schema sample
        data = evidence.get("data") if isinstance(evidence.get("data"), dict) else evidence.get("data")
        if data:
            schema = data.get("__schema") or data.get("__type")
            if schema and isinstance(schema, dict):
                types = schema.get("types")
                if types and isinstance(types, list):
                    sample = [t.get("name") for t in types[:25] if isinstance(t, dict) and t.get("name")]
                    if sample:
                        return "Types (sample): " + ", ".join(sample)
        # 4) Pretty JSON fallback
        try:
            s = json.dumps(evidence, indent=2, ensure_ascii=False)
            return s[:4000] + ("\n...[truncated]" if len(s) > 4000 else "")
        except Exception:
            return str(evidence)
    s = str(evidence)
    return s[:4000] + ("\n...[truncated]" if len(s) > 4000 else "")


def report_finding(findings, name, severity, *, evidence_obj=None, raw_text=None, fragment=None, meta=None, verify_curl=None):
    """
    Append finding; create ONE evidence JSON file ONLY for real issues (LOW/MEDIUM/HIGH).
    JSON contains: name, severity, timestamp, meta, fragment, evidence, raw, verify_curl (last key).
    Additionally, create a .txt file with the same base name containing a clean, human-readable rendering,
    including the *cleaned* verify_curl command (multi-line here-doc, not JSON-escaped).
    """
    idx = len(findings) + 1
    evidence = evidence_obj if evidence_obj is not None else {}
    record = {
        "name": name,
        "severity": severity,
        "meta": meta or {},
        "evidence": evidence,
        "raw": raw_text
    }
    findings.append(record)

    if severity not in VALID_SEVERITIES_FOR_FILES:
        return record  # no files for INFO

    # Payload to persist
    payload = {
        "name": name,
        "severity": severity,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "meta": meta or {},
        "fragment": (fragment or extract_fragment_from_evidence(evidence) or (raw_text or ""))[:4000],
        "evidence": evidence,
        "raw": raw_text,
        "verify_curl": verify_curl or ""
    }

    jpath = write_evidence_json(name, idx, severity, payload)
    tpath = write_evidence_txt(name, idx, severity, payload)
    print(colored(f"Evidence JSON: {jpath}", "cyan"))
    print(colored(f"Evidence TXT:  {tpath}", "cyan"))
    return record

# ---------------------------
# Checks (each passes verify_curl)
# ---------------------------

def check_introspection(url, headers, timeout, verify_tls, findings):
    payload = {'query': '{ __schema { types { name } } }'}
    code, hdrs, data, raw, tt = post_json(url, payload, headers, timeout, verify_tls)
    name = "Introspection enabled"
    meta = {"http_status": code, "latency_s": tt, "content_type": hdrs.get("Content-Type") if hdrs else None}
    if code in (401, 403) and not data:
        print(colored("[!] Introspection request blocked by edge/auth (HTTP %s)" % code, "yellow"))
        report_finding(findings, name, "INFO", evidence_obj={"blocked": True}, raw_text=raw, meta=meta)
        return False
    if data and isinstance(data, dict) and data.get("data", {}).get("__schema"):
        print_result(False, f"{name} at {url}")
        print(sev("LOW")("Typical severity: Low"))
        types = data.get("data", {}).get("__schema", {}).get("types")
        frag = None
        if types and isinstance(types, list):
            sample = [t.get("name") for t in types[:25] if isinstance(t, dict) and t.get("name")]
            frag = "Types (sample): " + ", ".join(sample)
        verify = build_curl_post(url, headers, payload, insecure=not verify_tls)
        report_finding(
            findings, name, "LOW",
            evidence_obj={"schema_sample": types[:50] if types else None},
            raw_text=json.dumps(data, indent=2, ensure_ascii=False),
            fragment=frag, meta=meta, verify_curl=verify
        )
        return True
    else:
        print_result(True, f"Introspection appears disabled or not exposed")
        report_finding(findings, name, "INFO", evidence_obj={"message": "disabled or not exposed"}, raw_text=raw, meta=meta)
        return False


def check_circular_introspection(url, headers, timeout, verify_tls, findings):
    payload = {'query': '''{
        __type(name: "Query") {
            name
            fields {
                name
                type {
                    name
                    kind
                    ofType {
                        name
                        kind
                        ofType {
                            name
                            kind
                            ofType {
                                name
                                kind
                            }
                        }
                    }
                }
            }
        }
    }''' }
    code, hdrs, data, raw, tt = post_json(url, payload, headers, timeout, verify_tls)
    name = "Circular introspection"
    meta = {"http_status": code, "latency_s": tt}
    if data and data.get("data", {}).get("__type"):
        print(colored(f"[!] {name} vulnerability found at {url}", "red"))
        print(sev("HIGH")("Typical severity: High"))
        frag = json.dumps(data.get("data", {}).get("__type"), indent=2, ensure_ascii=False)
        verify = build_curl_post(url, headers, payload, insecure=not verify_tls)
        report_finding(
            findings, name, "HIGH",
            evidence_obj={"data": data.get("data", {})},
            raw_text=frag, fragment=frag[:4000], meta=meta, verify_curl=verify
        )
    else:
        print(colored(f"[+] No {name} vulnerability found", "green"))
        report_finding(findings, name, "INFO", evidence_obj={"raw": raw}, raw_text=raw, meta=meta)


def check_introspection_bypass(url, headers, timeout, verify_tls, findings):
    variants = [
        {'query': 'query X { s: __schema { queryType { name } } }'},
        {'query': 'fragment F on __Schema { types { name } } query { __schema { ...F } }'},
        {'query': 'query($x:Boolean!){ __schema @include(if:$x){ types { name } } }', 'variables': {'x': True}}
    ]
    name = "Introspection blocklist bypass probes"
    hit_payload = None
    combined = []
    for payload in variants:
        code, hdrs, data, raw, tt = post_json(url, payload, headers, timeout, verify_tls)
        combined.append({"payload": payload, "http_status": code, "ct": hdrs.get("Content-Type") if hdrs else None, "data_present": bool(data and data.get("data"))})
        if data and data.get("data", {}).get("__schema"):
            hit_payload = payload
            break
    if hit_payload:
        print_result(False, f"{name}: succeeded")
        verify = build_curl_post(url, headers, hit_payload, insecure=not verify_tls)
        report_finding(findings, name, "MEDIUM",
                       evidence_obj={"results": combined},
                       raw_text=json.dumps(combined, indent=2, ensure_ascii=False),
                       fragment="Bypass worked with one of the probes.", meta={"hit": True},
                       verify_curl=verify)
    else:
        print_result(True, f"{name}: not effective")
        report_finding(findings, name, "INFO",
                       evidence_obj={"results": combined},
                       raw_text=json.dumps(combined, indent=2, ensure_ascii=False))


def check_suggestive_errors(url, headers, timeout, verify_tls, findings):
    rand_field = "x"+str(int(time.time()))
    payload = {'query': f'{{ {rand_field} }}'}
    code, hdrs, data, raw, tt = post_json(url, payload, headers, timeout, verify_tls)
    name = "Schema leakage via suggestive errors"
    suggestions = []
    if isinstance(data, dict) and "errors" in data:
        for e in data["errors"]:
            msg = e.get("message","")
            m = re.search(r'Did you mean "(.*?)"', msg)
            if m:
                suggestions.append(m.group(1))
    if suggestions:
        print_result(False, f"{name}: got suggestions -> {', '.join(suggestions[:5])}")
        verify = build_curl_post(url, headers, payload, insecure=not verify_tls)
        report_finding(findings, name, "LOW",
                       evidence_obj={"errors": data.get("errors")},
                       raw_text=json.dumps(data.get("errors"), indent=2, ensure_ascii=False),
                       fragment="\n".join(suggestions[:10]),
                       meta={"rand_field": rand_field},
                       verify_curl=verify)
    else:
        print_result(True, f"{name}: no suggestive hints")
        report_finding(findings, name, "INFO",
                       evidence_obj={"errors": data.get("errors") if isinstance(data, dict) else data},
                       raw_text=raw)


def check_deprecated_fields(url, headers, timeout, verify_tls, findings):
    payload = {'query': '{ __type(name:"Query"){ fields(includeDeprecated:true){ name isDeprecated deprecationReason } } }'}
    code, hdrs, data, raw, tt = post_json(url, payload, headers, timeout, verify_tls)
    name = "Deprecated field enumeration"
    fields = data and data.get("data", {}).get("__type", {}).get("fields") or []
    deprecated = [f for f in fields if f.get("isDeprecated")]
    if deprecated:
        print_result(False, f"{name}: found {len(deprecated)} deprecated fields")
        frag = "\n".join([f"{d.get('name')}: {d.get('deprecationReason')}" for d in deprecated[:50]])
        verify = build_curl_post(url, headers, payload, insecure=not verify_tls)
        report_finding(findings, name, "LOW",
                       evidence_obj={"fields": deprecated},
                       raw_text=json.dumps(deprecated, indent=2, ensure_ascii=False),
                       fragment=frag,
                       verify_curl=verify)
    else:
        print_result(True, f"{name}: none visible (or introspection blocked)")
        report_finding(findings, name, "INFO", evidence_obj={"fields": fields}, raw_text=raw)


def check_get_support(url, headers, timeout, verify_tls, findings):
    params = {'query': '{ __typename }'}
    code, hdrs, data, raw, tt, final_url = get_json(url, params, headers, timeout, verify_tls)
    name = "GET method enabled for GraphQL"
    if code and code < 500 and (data or (raw and "data" in raw)):
        print_result(False, f"{name}: {final_url}")
        verify = build_curl_get(url, headers, params, insecure=not verify_tls)
        report_finding(findings, name, "LOW",
                       evidence_obj={"url": final_url, "status": code, "body": data or raw},
                       raw_text=json.dumps(data if data else {"raw": raw}, indent=2, ensure_ascii=False),
                       fragment=str(data)[:2000] if data else raw[:2000],
                       verify_curl=verify)
    else:
        print_result(True, f"{name}: not supported")
        report_finding(findings, name, "INFO", evidence_obj={"status": code, "body": raw}, raw_text=raw)


def check_cors(url, headers, timeout, verify_tls, findings):
    try:
        r = requests.options(url, headers=headers, timeout=timeout, verify=verify_tls)
        acao = r.headers.get("Access-Control-Allow-Origin")
        acac = r.headers.get("Access-Control-Allow-Credentials")
        name = "CORS configuration"
        ev = {"Access-Control-Allow-Origin": acao, "Access-Control-Allow-Credentials": acac, "status": r.status_code}
        if (acao == "*" and (acac or "").lower() == "true") or (acao and acac and acac.lower()=="true"):
            print_result(False, f"{name}: Permissive ({acao}, credentials={acac})")
            verify = build_curl_options(url, headers, insecure=not verify_tls)
            report_finding(findings, name, "MEDIUM",
                           evidence_obj=ev,
                           raw_text=json.dumps(dict(r.headers), indent=2, ensure_ascii=False),
                           fragment=str(ev),
                           verify_curl=verify)
        else:
            print_result(True, f"{name}: No obvious risks ({acao}, credentials={acac})")
            report_finding(findings, name, "INFO", evidence_obj=ev,
                           raw_text=json.dumps(dict(r.headers), indent=2, ensure_ascii=False))
    except requests.exceptions.RequestException as e:
        print(colored(f"[!] CORS probe failed: {e}", "yellow"))
        report_finding(findings, "CORS probe failed", "INFO", evidence_obj={"error": str(e)})


def check_stacktrace_leak(url, headers, timeout, verify_tls, findings):
    payload = {'query': 'query($n:Int!){ __typename argThatDoesNotExist(n:$n) }', 'variables': {'n': "notAnInt"}}
    code, hdrs, data, raw, tt = post_json(url, payload, headers, timeout, verify_tls)
    name = "Stack trace / exception leakage"
    leaked, blob = looks_stacktrace(data.get("errors") if isinstance(data, dict) else [])
    if leaked:
        print_result(False, f"{name}: detailed traces exposed")
        frag = blob if isinstance(blob, str) else json.dumps(blob, indent=2, ensure_ascii=False)
        verify = build_curl_post(url, headers, payload, insecure=not verify_tls)
        report_finding(findings, name, "MEDIUM",
                       evidence_obj={"errors": data.get("errors")},
                       raw_text=json.dumps(data, indent=2, ensure_ascii=False),
                       fragment=frag[:4000],
                       verify_curl=verify)
    else:
        print_result(True, f"{name}: no stack traces visible")
        report_finding(findings, name, "INFO",
                       evidence_obj={"errors": data.get("errors") if isinstance(data, dict) else data},
                       raw_text=raw)


def check_alias_pressure(url, headers, timeout, verify_tls, alias_count, findings):
    fields = " ".join([f't{i}: __typename' for i in range(alias_count)])
    payload = {'query': f'{{ {fields} }}'}
    code, hdrs, data, raw, tt = post_json(url, payload, headers, timeout, verify_tls)
    name = "Alias pressure (complexity without depth)"
    evidence = {"aliases": alias_count, "latency_s": tt, "status": code}
    if code and code < 500 and tt and tt > 2.0:
        print_result(False, f"{name}: slow response ({tt:.2f}s) with {alias_count} aliases")
        verify = build_curl_post(url, headers, payload, insecure=not verify_tls)
        report_finding(findings, name, "LOW",
                       evidence_obj=evidence,
                       raw_text=json.dumps(data if data else {"raw": raw}, indent=2, ensure_ascii=False),
                       fragment=f"Latency: {tt:.2f}s with {alias_count} aliases",
                       verify_curl=verify)
    else:
        print_result(True, f"{name}: handled {alias_count} aliases in {0.0 if not tt else tt:.2f}s")
        report_finding(findings, name, "INFO", evidence_obj=evidence,
                       raw_text=json.dumps(data if data else {"raw": raw}, indent=2, ensure_ascii=False))


def check_fragment_explosion(url, headers, timeout, verify_tls, frag_count, findings):
    frags = "\n".join([f'fragment F{i} on Query {{ __typename }}' for i in range(frag_count)])
    spreads = " ".join([f'...F{i}' for i in range(frag_count)])
    payload = {'query': f'{frags}\nquery Q{{ {spreads} }}'}
    code, hdrs, data, raw, tt = post_json(url, payload, headers, timeout, verify_tls)
    name = "Fragment explosion pressure"
    evidence = {"fragments": frag_count, "latency_s": tt, "status": code}
    if code and code < 500 and tt and tt > 2.0:
        print_result(False, f"{name}: slow response ({tt:.2f}s) with {frag_count} fragments")
        verify = build_curl_post(url, headers, payload, insecure=not verify_tls)
        report_finding(findings, name, "LOW",
                       evidence_obj=evidence,
                       raw_text=json.dumps(data if data else {"raw": raw}, indent=2, ensure_ascii=False),
                       fragment=f"Latency: {tt:.2f}s with {frag_count} fragments",
                       verify_curl=verify)
    else:
        print_result(True, f"{name}: handled {frag_count} fragments in {0.0 if not tt else tt:.2f}s")
        report_finding(findings, name, "INFO", evidence_obj=evidence,
                       raw_text=json.dumps(data if data else {"raw": raw}, indent=2, ensure_ascii=False))


def check_defer_stream(url, headers, timeout, verify_tls, findings):
    name = "Support for @defer/@stream directives"
    payload_defer = {'query': 'query { __typename @defer }'}
    code_d, hdrs_d, data_d, raw_d, tt_d = post_json(url, payload_defer, headers, timeout, verify_tls)
    payload_stream = {'query': 'query { __schema { types @stream } }'}
    code_s, hdrs_s, data_s, raw_s, tt_s = post_json(url, payload_stream, headers, timeout, verify_tls)
    supported = (data_d and (not data_d.get("errors"))) or (data_s and (not data_s.get("errors")))
    if supported:
        print_result(False, f"{name}: appears supported")
        verify = build_curl_post(url, headers, payload_defer, insecure=not verify_tls)
        report_finding(findings, name, "LOW",
                       evidence_obj={"defer": data_d, "stream": data_s},
                       raw_text=json.dumps({"defer": data_d, "stream": data_s}, indent=2, ensure_ascii=False),
                       verify_curl=verify)
    else:
        print_result(True, f"{name}: not supported or blocked")
        report_finding(findings, name, "INFO",
                       evidence_obj={"defer": data_d, "stream": data_s},
                       raw_text=json.dumps({"defer": data_d, "stream": data_s}, indent=2, ensure_ascii=False))


def check_deeply_nested(url, headers, timeout, verify_tls, depth, findings):
    depth = max(2, min(depth, 8))
    payload = {'query': "{ " + " ".join(["__typename" for _ in range(depth)]) + " }"}
    code, hdrs, data, raw, tt = post_json(url, payload, headers, timeout, verify_tls)
    name = "Deep query handling (depth limit)"
    evidence = {"depth_requested": depth, "latency_s": tt, "status": code}
    if code and code < 500 and tt and tt > 2.5:
        print_result(False, f"{name}: slow at depth {depth} ({tt:.2f}s)")
        verify = build_curl_post(url, headers, payload, insecure=not verify_tls)
        report_finding(findings, name, "LOW",
                       evidence_obj=evidence,
                       raw_text=json.dumps(data if data else {"raw": raw}, indent=2, ensure_ascii=False),
                       fragment=f"Latency: {tt:.2f}s at depth {depth}",
                       verify_curl=verify)
    else:
        print_result(True, f"{name}: depth {depth} OK ({0.0 if not tt else tt:.2f}s)")
        report_finding(findings, name, "INFO",
                       evidence_obj=evidence,
                       raw_text=json.dumps(data if data else {"raw": raw}, indent=2, ensure_ascii=False))


def check_batching_isolation(url, headers, timeout, verify_tls, batch_size, findings):
    batch = []
    for i in range(batch_size):
        if i % 2 == 0:
            batch.append({'query': '{ __typename }'})
        else:
            batch.append({'query': '{ doesNotExist }'})
    payload = batch
    code, hdrs, data, raw, tt = post_json(url, payload, headers, timeout, verify_tls)
    name = "Batching behavior & isolation"
    if isinstance(data, list) and len(data) == batch_size:
        errs = sum(1 for d in data if isinstance(d, dict) and d.get("errors"))
        ok = sum(1 for d in data if isinstance(d, dict) and d.get("data"))
        print_result(False, f"{name}: batch accepted (OK={ok}, ERR={errs})")
        verify = build_curl_post(url, headers, payload, insecure=not verify_tls)
        report_finding(findings, name, "LOW",
                       evidence_obj={"ok": ok, "errors": errs, "responses": data},
                       raw_text=json.dumps(data, indent=2, ensure_ascii=False),
                       verify_curl=verify)
    else:
        print_result(True, f"{name}: batch not accepted or filtered")
        report_finding(findings, name, "INFO",
                       evidence_obj={"status": code, "raw": raw},
                       raw_text=raw)


def check_dev_ui_exposure(base_url, headers, timeout, verify_tls, findings):
    candidates = [
        base_url,
        base_url.rstrip("/") + "/graphiql",
        base_url.rstrip("/") + "/graphql",
        base_url.rstrip("/") + "/playground",
        base_url.rstrip("/") + "/altair"
    ]
    name = "Developer UI exposure (GraphiQL/Playground/Altair)"
    hits = []
    for u in candidates:
        try:
            r = requests.get(u, headers=headers, timeout=timeout, verify=verify_tls)
            if r.status_code < 400 and ("GraphiQL" in r.text or "Playground" in r.text or "Altair" in r.text):
                hits.append({"url": u, "status": r.status_code, "snippet": r.text[:1200]})
        except requests.exceptions.RequestException:
            pass
    if hits:
        print_result(False, f"{name}: {', '.join(h['url'] for h in hits)}")
        verify = f"curl -i -sS {sh_quote(hits[0]['url'])}"
        report_finding(findings, name, "LOW",
                       evidence_obj={"hits": hits},
                       raw_text=json.dumps(hits, indent=2, ensure_ascii=False),
                       fragment="\n".join([h.get("snippet","") for h in hits])[:4000],
                       verify_curl=verify)
    else:
        print_result(True, f"{name}: not obviously exposed")
        report_finding(findings, name, "INFO", evidence_obj={"hits": hits})


def check_directive_limit(url, headers, timeout, verify_tls, findings):
    # UPDATED: enumerate directives via __schema { directives { ... } }
    payload = {'query': '''
    {
      __schema {
        directives {
          name
          locations
          args {
            name
            type { kind name ofType { kind name } }
          }
        }
      }
    }'''}
    code, hdrs, data, raw, tt = post_json(url, payload, headers, timeout, verify_tls)
    name = "Directive enumeration"
    if data and data.get("data", {}).get("__schema", {}).get("directives"):
        print_result(False, f"{name}: directives visible")
        verify = build_curl_post(url, headers, payload, insecure=not verify_tls)
        report_finding(findings, name, "LOW",
                       evidence_obj={"directives": data.get("data", {}).get("__schema", {}).get("directives")},
                       raw_text=json.dumps(data, indent=2, ensure_ascii=False),
                       verify_curl=verify)
    else:
        print_result(True, f"{name}: directives not visible (blocked)")
        report_finding(findings, name, "INFO",
                       evidence_obj={"status": code, "raw": raw},
                       raw_text=raw)


def check_resource_request(url, headers, timeout, verify_tls, type_name, findings):
    payload = {'query': f'{{ __type(name:"{type_name}"){{ name fields {{ name type {{ name kind ofType {{ name kind }} }} }} }} }}'}
    code, hdrs, data, raw, tt = post_json(url, payload, headers, timeout, verify_tls)
    name = f"Excessive resource request for type {type_name}"
    if data and data.get("data", {}).get("__type"):
        print_result(False, f"{name}: type disclosed")
        verify = build_curl_post(url, headers, payload, insecure=not verify_tls)
        report_finding(findings, name, "HIGH",
                       evidence_obj={"type": data.get("data", {})},
                       raw_text=json.dumps(data, indent=2, ensure_ascii=False),
                       verify_curl=verify)
    else:
        print_result(True, f"{name}: type not disclosed (or blocked)")
        report_finding(findings, name, "INFO",
                       evidence_obj={"status": code, "raw": raw},
                       raw_text=raw)

# ---------------------------
# Main
# ---------------------------

def main():
    parser = argparse.ArgumentParser(description="GraphQL endpoint vulnerability checks (extended).")
    parser.add_argument('-t', '--target', required=True, help="Target GraphQL endpoint URL (POST endpoint).")
    parser.add_argument('-H', '--header', action='append', help='Extra header "Name: Value" (repeatable).')
    parser.add_argument('--insecure', action='store_true', help='Allow insecure TLS (verify=False).')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, help='Per-request timeout seconds.')
    parser.add_argument('--aliases', type=int, default=50, help='Alias count for alias pressure test.')
    parser.add_argument('--fragments', type=int, default=50, help='Fragment count for explosion test.')
    parser.add_argument('--depth', type=int, default=6, help='Requested depth for deep queries (2..8).')
    parser.add_argument('--batch', type=int, default=8, help='Batch size for batching test.')
    parser.add_argument('--type', default='User', help='Type name to probe in resource request test.')
    parser.add_argument('--json', action='store_true', help='Output JSON findings to stdout at the end.')
    args = parser.parse_args()

    target = args.target
    headers = parse_headers(args.header)
    verify_tls = not args.insecure
    findings = []

    print(colored(f"Starting GraphQL checks against: {target}", "cyan"))

    # Core visibility / controls
    introspection = check_introspection(target, headers, args.timeout, verify_tls, findings)
    if introspection:
        check_circular_introspection(target, headers, args.timeout, verify_tls, findings)
    check_introspection_bypass(target, headers, args.timeout, verify_tls, findings)
    check_suggestive_errors(target, headers, args.timeout, verify_tls, findings)
    check_deprecated_fields(target, headers, args.timeout, verify_tls, findings)

    # Transport & perimeter controls
    check_get_support(target, headers, args.timeout, verify_tls, findings)
    check_cors(target, headers, args.timeout, verify_tls, findings)
    check_stacktrace_leak(target, headers, args.timeout, verify_tls, findings)

    # Resource pressure (safe defaults)
    check_alias_pressure(target, headers, args.timeout, verify_tls, args.aliases, findings)
    check_fragment_explosion(target, headers, args.timeout, verify_tls, args.fragments, findings)
    check_deeply_nested(target, headers, args.timeout, verify_tls, args.depth, findings)
    check_batching_isolation(target, headers, args.timeout, verify_tls, args.batch, findings)

    # Feature flags / dev surfaces
    check_defer_stream(target, headers, args.timeout, verify_tls, findings)
    check_dev_ui_exposure(target, headers, args.timeout, verify_tls, findings)

    # Schema/data breadth probes
    check_resource_request(target, headers, args.timeout, verify_tls, args.type, findings)
    check_directive_limit(target, headers, args.timeout, verify_tls, findings)

    # Final summary
    high = [f for f in findings if f.get("severity") == "HIGH"]
    med  = [f for f in findings if f.get("severity") == "MEDIUM"]
    low  = [f for f in findings if f.get("severity") == "LOW"]
    info = [f for f in findings if f.get("severity") == "INFO"]
    print("\n" + colored("=== Summary ===", "magenta"))
    print(colored(f"HIGH: {len(high)}  MEDIUM: {len(med)}  LOW: {len(low)}  INFO: {len(info)}", "magenta"))
    print(colored("Evidence JSON/TXT files are written only for LOW/MEDIUM/HIGH findings, with severity-prefixed basenames and a clean verify_curl.", "cyan"))
    if args.json:
        print(json.dumps({"target": target, "findings": findings}, indent=2, default=str))


if __name__ == "__main__":
    main()

