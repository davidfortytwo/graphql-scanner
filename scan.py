#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Enhanced GraphQL Scanner with authentication, safety and error handling

import argparse
import requests
import json
import time
import sys
import threading
from termcolor import colored
from datetime import datetime

warned_hosts = {}
log_file = None
throttle = 0.5
verbose = False
stop_spinner = False
custom_headers = {}

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

# === CHECK FUNCTIONS ===

def check_introspection(url):
    query = {'query': '{ __schema { types { name } } }'}
    response_json = send_query(url, query)
    if not response_json:
        log(colored("[!] No response or invalid JSON received for introspection query.", "yellow"))
        return False
    if 'data' in response_json and '__schema' in response_json['data']:
        log(colored(f"[!] Introspection is enabled at {url}", "red"))
        log(colored("Typical severity: Low", "blue"))
        log("Evidence:\n" + json.dumps(response_json, indent=4))
        return True
    else:
        log(colored(f"[-] Introspection is not enabled at {url}", "green"))
        return False

def check_circular_introspection(url):
    query = {
        'query': '''{
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
        }'''
    }
    response_json = send_query(url, query)
    if not response_json:
        log(colored("[!] No response or invalid JSON received for circular introspection.", "yellow"))
        return
    if 'data' in response_json and '__type' in response_json['data']:
        log(colored(f"[!] Circular introspection vulnerability found at {url}", "red"))
        log(colored("Typical severity: High", "red"))
        log("Evidence:\n" + json.dumps(response_json, indent=4))
    else:
        log(colored(f"[-] No circular introspection vulnerability found at {url}", "green"))

def check_deeply_nested_query(url):
    query = {'query': '{ a1: __schema { queryType { name, fields { name, type { name, fields { name, type { name } } } } } } }'}
    response_json = send_query(url, query)
    if not response_json:
        log(colored("[!] No response or invalid JSON received for deeply nested query.", "yellow"))
        return
    if 'data' in response_json:
        log(colored(f"[!] Server responds to deeply nested queries at {url}. Possible DoS vulnerability.", "red"))
    else:
        log(colored(f"[-] No issues with deeply nested queries found at {url}.", "green"))

def check_batch_requests(url):
    batch_query = [{'query': '{ __schema { types { name } } }'}] * 10
    response_json = send_query(url, batch_query)
    if not response_json:
        log(colored("[!] No response or invalid JSON received for batch request.", "yellow"))
        return
    log(colored(f"[!] Server allows batch requests at {url}. May lead to DoS if abused.", "red"))

def check_resource_request(url):
    query = {'query': '{ __type(name: "User") { name fields { name type { name kind ofType { name kind } } } } }'}
    response_json = send_query(url, query)
    if not response_json:
        log(colored("[!] No response or invalid JSON received for resource request.", "yellow"))
        return
    if 'data' in response_json and '__type' in response_json['data']:
        log(colored(f"[!] Excessive resource request vulnerability found at {url}", "red"))
        log(colored("Typical severity: High", "red"))
        log("Evidence:\n" + json.dumps(response_json, indent=4))
    else:
        log(colored(f"[-] No excessive resource request vulnerability found at {url}", "green"))

def check_directive_limit(url):
    query = {'query': '{ __type(name: "Directive") { name locations args { name type { name kind } } } }'}
    response_json = send_query(url, query)
    if not response_json:
        log(colored("[!] No response or invalid JSON received for directive check.", "yellow"))
        return
    if 'data' in response_json and '__type' in response_json['data']:
        log(colored(f"[!] Unlimited number of directives vulnerability found at {url}", "red"))
        log(colored("Typical severity: Low", "blue"))
        log("Evidence:\n" + json.dumps(response_json, indent=4))
    else:
        log(colored(f"[-] No unlimited number of directives vulnerability found at {url}", "green"))

def check_error_based_enumeration(url):
    query = {'query': '{ thisDoesNotExist }'}
    response_json = send_query(url, query)
    if not response_json:
        log(colored("[!] No response or invalid JSON received for error enumeration.", "yellow"))
        return
    if 'errors' in response_json:
        verbose_msgs = [e['message'] for e in response_json['errors'] if 'Did you mean' in e.get('message', '') or 'Cannot query field' in e.get('message', '')]
        if verbose_msgs:
            log(colored(f"[!] Verbose error messages detected at {url}", "red"))
            log(colored("Typical severity: Medium", "blue"))
            log("Evidence:\n" + json.dumps(response_json['errors'], indent=4))
        else:
            log(colored(f"[-] Error messages are not verbose at {url}", "green"))

def check_authorization_bypass(url):
    for typename in ["User", "Admin", "Token", "Account"]:
        query = {'query': f'{{ __type(name: "{typename}") {{ name fields {{ name }} }} }}'}
        response_json = send_query(url, query)
        if not response_json:
            continue
        if response_json.get('data', {}).get('__type'):
            log(colored(f"[!] Possible auth bypass – access to '{typename}' type without auth at {url}", "red"))
            log("Evidence:\n" + json.dumps(response_json, indent=4))

def check_field_suggestion(url):
    query = {'query': '{ useer { id } }'}
    response_json = send_query(url, query)
    if not response_json:
        log(colored("[!] No response or invalid JSON received for field suggestion.", "yellow"))
        return
    if 'errors' in response_json:
        suggestions = [e['message'] for e in response_json['errors'] if 'Did you mean' in e.get('message', '')]
        if suggestions:
            log(colored(f"[!] Field suggestion leak detected at {url}", "red"))
            log(colored("Typical severity: Medium", "blue"))
            for s in suggestions:
                log(s)
        else:
            log(colored(f"[-] No suggestion-based leakage at {url}", "green"))

def check_rate_limiting(url):
    query = {'query': '{ __schema { types { name } } }'}
    codes = []
    for _ in range(5):
        try:
            resp = requests.post(url, json=query, headers=custom_headers)
            codes.append(resp.status_code)
            time.sleep(0.3)
        except Exception as e:
            log(f"[!] Rate check error: {e}")
    if 429 in codes or any(c == 403 for c in codes):
        log(colored(f"[!] Possible rate limiting detected at {url}", "yellow"))
        log(f"Status Codes: {codes}")
    else:
        log(colored(f"[-] No rate limiting detected at {url}", "green"))

def check_fake_type_discovery(url):
    for typename in ["Token", "Session", "PrivateData", "SecretUser"]:
        query = {'query': f'{{ __type(name: "{typename}") {{ name }} }}'}
        response_json = send_query(url, query)
        if not response_json:
            continue
        if response_json.get('data', {}).get('__type'):
            log(colored(f"[!] Discovered undocumented type '{typename}' at {url}", "red"))

def check_token_field_leak(url):
    query = {'query': '{ __type(name: "User") { fields { name } } }'}
    response_json = send_query(url, query)
    if not response_json:
        log(colored("[!] No response or invalid JSON received for token leak check.", "yellow"))
        return
    fields = [f['name'] for f in response_json['data']['__type'].get('fields', [])]
    leaks = [f for f in fields if any(k in f.lower() for k in ['token', 'password', 'secret', 'apikey', 'auth'])]
    if leaks:
        log(colored(f"[!] Sensitive fields found in 'User' type: {', '.join(leaks)}", "red"))
    else:
        log(colored("[-] No sensitive fields found in 'User' type", "green"))

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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GraphQL Security Scanner")
    parser.add_argument('-t', '--target', required=True, help="Target GraphQL endpoint.")
    parser.add_argument('--safe-mode', action='store_true', help="Enable safe mode to avoid DoS risk.")
    parser.add_argument('--throttle', type=float, default=0.5, help="Delay between requests in seconds.")
    parser.add_argument('--verbose', action='store_true', help="Enable debug output.")
    parser.add_argument('--cookie', type=str, help="Cookie string (do not include 'Cookie:' prefix).")
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
