#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# GraphQL Scanner by David Espejo + Enhanced by Techno Guardian

import argparse
import requests
import json
import time
import sys
import threading
from termcolor import colored
from datetime import datetime
from collections import defaultdict

warned_hosts = {}
log_file = None
throttle = 0.5
verbose = False
stop_spinner = False
custom_headers = {}
schema_coverage = defaultdict(int)
sensitive_keywords = ['token', 'password', 'secret', 'apikey', 'auth', 'credential', 'git']

def log(msg):
    print(msg)
    if log_file:
        log_file.write(msg + "\n")

def debug(msg):
    if verbose:
        log("[DEBUG] " + msg)

def spinner():
    while not stop_spinner:
        for ch in "|/-\\":
            if stop_spinner:
                break
            sys.stdout.write(f"\r{ch} Scanning...")
            sys.stdout.flush()
            time.sleep(0.1)

def send_query(url, query):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    headers.update(custom_headers)

    time.sleep(throttle)

    try:
        response = requests.post(url, json=query, headers=headers, timeout=10)
        debug(f"Response status: {response.status_code}")
        debug(f"Response headers: {dict(response.headers)}")
        debug(f"Response body: {response.text[:300]}...")

        content_type = response.headers.get('Content-Type', '')
        if response.status_code != 200:
            log(colored(f"[!] HTTP error {response.status_code} for {url}", "red"))
            return None

        if 'application/json' in content_type:
            return response.json()
        else:
            log(colored(f"[!] Unexpected Content-Type: {content_type}", "yellow"))
            return None

    except requests.exceptions.RequestException as e:
        log(colored(f"[!] Request failed: {e}", "red"))
        return None

def classify_fields(fields):
    classified = {"SCALAR": 0, "OBJECT": 0, "LIST": 0, "ENUM": 0, "SENSITIVE": []}
    for f in fields:
        fname = f.get("name", "")
        ftype = f.get("type", {})
        kind = ftype.get("kind")
        name = ftype.get("name")
        oftype = ftype.get("ofType")

        # Detect sensitive by name
        if any(keyword in fname.lower() for keyword in sensitive_keywords):
            classified["SENSITIVE"].append(fname)

        # Unwrap nested types
        while oftype:
            kind = oftype.get("kind")
            name = oftype.get("name")
            oftype = oftype.get("ofType")

        classified[kind or "UNKNOWN"] += 1
    return classified

def estimate_depth(ftype, level=1):
    if not isinstance(ftype, dict):
        return level
    oftype = ftype.get("ofType")
    if oftype:
        return estimate_depth(oftype, level + 1)
    return level

def check_resource_request(url):
    query = {'query': '{ __type(name: "User") { name fields { name type { name kind ofType { name kind ofType { name kind } } } } } }'}
    response_json = send_query(url, query)
    if not isinstance(response_json, dict):
        log(colored("[!] No response or invalid JSON for resource request.", "yellow"))
        return

    user_type = response_json.get("data", {}).get("__type", {})
    fields = user_type.get("fields", [])
    if not fields:
        log(colored("[-] No fields found in 'User' type", "green"))
        return

    schema_coverage['types_queried'] += 1
    schema_coverage['fields_total'] += len(fields)

    classified = classify_fields(fields)
    depth_scores = [estimate_depth(f.get("type", {})) for f in fields]

    log(colored(f"[!] Excessive resource request vulnerability found at {url}", "red"))
    log(colored("Typical severity: High", "red"))
    log(f"Field count: {len(fields)}")
    log(f"Max field depth: {max(depth_scores)}")
    log(f"Classification: {json.dumps(classified, indent=2)}")

    if classified['SENSITIVE']:
        log(colored(f"[!] Sensitive fields detected: {', '.join(classified['SENSITIVE'])}", "red"))

    log("Evidence:\n" + json.dumps(response_json, indent=4))

def check_authorization_bypass(url):
    authenticated = 'Cookie' in custom_headers or 'Authorization' in custom_headers
    types = ["User", "Admin", "Token", "Account"]
    for typename in types:
        query = {'query': f'{{ __type(name: "{typename}") {{ name fields {{ name }} }} }}'}
        response_json = send_query(url, query)
        if not isinstance(response_json, dict):
            continue
        if response_json.get('data', {}).get('__type'):
            if authenticated:
                log(colored(f"[!] Access to sensitive type '{typename}' detected with authentication.", "yellow"))
                log(colored("Note: This may be valid based on your session. Manual review recommended.", "blue"))
            else:
                log(colored(f"[!] Possible auth bypass – access to '{typename}' type without auth at {url}", "red"))
            log("Evidence:\n" + json.dumps(response_json, indent=4))
            schema_coverage['types_queried'] += 1

def check_token_field_leak(url):
    query = {'query': '{ __type(name: "User") { fields { name } } }'}
    response_json = send_query(url, query)
    if not isinstance(response_json, dict):
        log(colored("[!] No response or invalid JSON for token leak check.", "yellow"))
        return

    fields = response_json.get('data', {}).get('__type', {}).get('fields', [])
    leaks = [f['name'] for f in fields if any(k in f['name'].lower() for k in sensitive_keywords)]
    if leaks:
        log(colored(f"[!] Sensitive fields found in 'User' type: {', '.join(leaks)}", "red"))
        schema_coverage['fields_sensitive'] += len(leaks)
        for field in leaks:
            resolve_sensitive_field(url, field)
    else:
        log(colored("[-] No sensitive fields found in 'User' type", "green"))

def resolve_sensitive_field(url, field_name):
    query = {'query': f'{{ user {{ {field_name} }} }}'}
    response_json = send_query(url, query)
    if not isinstance(response_json, dict):
        log(colored(f"[!] Could not resolve sensitive field '{field_name}'", "yellow"))
        return
    data = response_json.get('data', {}).get('user')
    if data and data.get(field_name) is not None:
        log(colored(f"[!] Sensitive field '{field_name}' returned data!", "red"))
        log("Partial data:\n" + json.dumps(data, indent=2))
    else:
        log(colored(f"[-] Sensitive field '{field_name}' is not resolvable with current auth", "green"))


def summarize_schema_coverage():
    log("\n=== Schema Coverage Summary ===")
    log(f"🔎 Types queried: {schema_coverage['types_queried']}")
    log(f"📐 Total fields seen: {schema_coverage['fields_total']}")
    log(f"🔐 Sensitive fields flagged: {schema_coverage['fields_sensitive']}")
    if schema_coverage['fields_sensitive'] > 0:
        log(colored("⚠️  Sensitive fields should be manually audited or masked at schema level.", "red"))
    else:
        log(colored("✅ No sensitive fields found in accessible types.", "green"))

def run_all_checks(target, safe_mode):
    log(f"Scanning target: {target}")

    if check_introspection(target):
        check_circular_introspection(target)
        if not safe_mode:
            check_deeply_nested_query(target)
            check_batch_requests(target)
    else:
        log(colored("[*] Skipping circular/deep/batch checks due to introspection being disabled", "yellow"))

    check_resource_request(target)
    check_directive_limit(target)
    check_error_based_enumeration(target)
    check_authorization_bypass(target)
    check_field_suggestion(target)
    if not safe_mode:
        check_rate_limiting(target)
    check_fake_type_discovery(target)
    check_token_field_leak(target)

    summarize_schema_coverage()

# Reusa check_introspection() y otras si ya las tienes. Solo omitir si ya están integradas en tu versión actual.

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GraphQL Security Scanner - Enhanced Version")
    parser.add_argument('-t', '--target', required=True, help="Target GraphQL endpoint.")
    parser.add_argument('--safe-mode', action='store_true', help="Avoid DoS-prone checks.")
    parser.add_argument('--throttle', type=float, default=0.5, help="Delay between requests.")
    parser.add_argument('--verbose', action='store_true', help="Enable debug output.")
    parser.add_argument('--cookie', type=str, help="Cookie string (without 'Cookie:').")
    parser.add_argument('--bearer', type=str, help="Bearer token for Authorization header.")

    args = parser.parse_args()
    verbose = args.verbose
    throttle = args.throttle

    if args.cookie:
        custom_headers['Cookie'] = args.cookie
    if args.bearer:
        custom_headers['Authorization'] = f"Bearer {args.bearer}"

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"graphql_scan_report_{timestamp}.txt"

    with open(report_file, 'w') as f:
        log_file = f
        log(f"=== GraphQL Scan Report ===")
        log(f"Target: {args.target}")
        log(f"Safe Mode: {'ON' if args.safe_mode else 'OFF'}")
        log(f"Throttle: {throttle} seconds")
        log(f"Verbose: {'ON' if verbose else 'OFF'}")
        log(f"Cookie Set: {'YES' if args.cookie else 'NO'}")
        log(f"Bearer Token Set: {'YES' if args.bearer else 'NO'}\n")

        spinner_thread = threading.Thread(target=spinner)
        spinner_thread.start()

        try:
            run_all_checks(args.target, args.safe_mode)
        finally:
            stop_spinner = True
            spinner_thread.join()
            print("\n✅ Scan completed. Report saved to:", report_file)
