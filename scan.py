#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Original Author: David Espejo (Fortytwo Security)

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

    time.sleep(throttle)

    try:
        response = requests.post(url, json=query, headers=headers, timeout=10)
        content_type = response.headers.get('Content-Type', '')
        host_key = f"{url}:{response.status_code}"

        if response.status_code != 200:
            if host_key not in warned_hosts:
                log(colored(f"[!] HTTP error {response.status_code} for {url}", "red"))
                warned_hosts[host_key] = True
            return None

        if 'application/json' in content_type:
            return response.json()
        else:
            if f"{url}:content_type" not in warned_hosts:
                log(colored(f"[!] Unexpected Content-Type received from {url}: {content_type}", "yellow"))
                warned_hosts[f"{url}:content_type"] = True
            return None

    except requests.exceptions.RequestException as e:
        if f"{url}:exception" not in warned_hosts:
            log(colored(f"[!] Request exception for {url}: {e}", "red"))
            warned_hosts[f"{url}:exception"] = True
        return None

def check_introspection(url):
    introspection_query = {
        'query': '''{
            __schema {
                types {
                    name
                }
            }
        }'''
    }
    response_json = send_query(url, introspection_query)
    if response_json and 'data' in response_json and '__schema' in response_json['data']:
        log(colored(f"[!] Introspection is enabled at {url}", "red"))
        log(colored(f"Typical severity: Low", "blue"))
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
    if response_json and 'data' in response_json and '__type' in response_json['data']:
        log(colored(f"[!] Circular introspection vulnerability found at {url}", "red"))
        log(colored(f"Typical severity: High", "red"))
        log("Evidence:\n" + json.dumps(response_json, indent=4))
    else:
        log(colored(f"[-] No circular introspection vulnerability found at {url}", "green"))

def check_deeply_nested_query(url):
    query = {
        'query': '{ a1: __schema { queryType { name, fields { name, type { name, fields { name, type { name } } } } } } }'
    }
    response_json = send_query(url, query)
    if response_json and 'data' in response_json:
        log(colored(f"[!] Server responds to deeply nested queries at {url}. Possible DoS vulnerability.", "red"))
    else:
        log(colored(f"[-] No issues with deeply nested queries found at {url}.", "green"))

def check_batch_requests(url):
    batch_query = [{'query': '{ __schema { types { name } } }'}] * 10
    response_json = send_query(url, batch_query)
    if response_json:
        log(colored(f"[!] Server allows batch requests at {url}. May lead to DoS if abused.", "red"))
    else:
        log(colored(f"[-] No batch request vulnerability found at {url}.", "green"))

def check_resource_request(url):
    query = {
        'query': '''{
            __type(name: "User") {
                name
                fields {
                    name
                    type {
                        name
                        kind
                        ofType {
                            name
                            kind
                        }
                    }
                }
            }
        }'''
    }
    response_json = send_query(url, query)
    if response_json and 'data' in response_json and '__type' in response_json['data']:
        log(colored(f"[!] Excessive resource request vulnerability found at {url}", "red"))
        log(colored(f"Typical severity: High", "red"))
        log("Evidence:\n" + json.dumps(response_json, indent=4))
    else:
        log(colored(f"[-] No excessive resource request vulnerability found at {url}", "green"))

def check_directive_limit(url):
    query = {
        'query': '''{
            __type(name: "Directive") {
                name
                locations
                args {
                    name
                    type {
                        name
                        kind
                    }
                }
            }
        }'''
    }
    response_json = send_query(url, query)
    if response_json and 'data' in response_json and '__type' in response_json['data']:
        log(colored(f"[!] Unlimited number of directives vulnerability found at {url}", "red"))
        log(colored(f"Typical severity: Low", "blue"))
        log("Evidence:\n" + json.dumps(response_json, indent=4))
    else:
        log(colored(f"[-] No unlimited number of directives vulnerability found at {url}", "green"))

def check_error_based_enumeration(url):
    query = {'query': '{ thisDoesNotExist }'}
    response_json = send_query(url, query)
    if response_json and 'errors' in response_json:
        verbose_msgs = [e['message'] for e in response_json['errors'] if 'Did you mean' in e.get('message', '') or 'Cannot query field' in e.get('message', '')]
        if verbose_msgs:
            log(colored(f"[!] Verbose error messages detected at {url}", "red"))
            log(colored("Typical severity: Medium", "blue"))
            log("Evidence:\n" + json.dumps(response_json['errors'], indent=4))
        else:
            log(colored(f"[-] Error messages are not verbose at {url}", "green"))

def check_authorization_bypass(url):
    types = ["User", "Admin", "Token", "Account"]
    for typename in types:
        query = {'query': f'''{{ __type(name: "{typename}") {{ name fields {{ name }} }} }}'''}
        response_json = send_query(url, query)
        if response_json and response_json.get('data', {}).get('__type'):
            log(colored(f"[!] Possible auth bypass – access to '{typename}' type without auth at {url}", "red"))
            log("Evidence:\n" + json.dumps(response_json, indent=4))

def check_field_suggestion(url):
    query = {'query': '{ useer { id } }'}
    response_json = send_query(url, query)
    if response_json and 'errors' in response_json:
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
            resp = requests.post(url, json=query, headers={'Content-Type': 'application/json'})
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
    candidates = ["Token", "Session", "PrivateData", "SecretUser"]
    for typename in candidates:
        query = {'query': f'{{ __type(name: "{typename}") {{ name }} }}'}
        response_json = send_query(url, query)
        if response_json and response_json.get('data', {}).get('__type'):
            log(colored(f"[!] Discovered undocumented type '{typename}' at {url}", "red"))

def check_token_field_leak(url):
    query = {
        'query': '''{
            __type(name: "User") {
                fields {
                    name
                }
            }
        }'''
    }
    response_json = send_query(url, query)
    if response_json:
        fields = [f['name'] for f in response_json['data']['__type'].get('fields', [])]
        keywords = ['token', 'password', 'secret', 'apikey', 'auth']
        leaks = [f for f in fields if any(k in f.lower() for k in keywords)]
        if leaks:
            log(colored(f"[!] Sensitive fields found in 'User' type: {', '.join(leaks)}", "red"))
        else:
            log(colored("[-] No sensitive fields found in 'User' type", "green"))

def run_all_checks(target, safe_mode):
    log(f"Scanning target: {target}")

    # Introspection and related
    if check_introspection(target):
        check_circular_introspection(target)
        if not safe_mode:
            check_deeply_nested_query(target)
            check_batch_requests(target)
    else:
        log(colored("[*] Skipping circular/deep/batch checks due to introspection being disabled", "yellow"))

    # Independent checks
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
    args = parser.parse_args()

    verbose = args.verbose
    throttle = args.throttle
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"graphql_scan_report_{timestamp}.txt"

    with open(report_file, 'w') as f:
        log_file = f
        log(f"=== GraphQL Scan Report ===")
        log(f"Target: {args.target}")
        log(f"Safe Mode: {'ON' if args.safe_mode else 'OFF'}")
        log(f"Throttle: {throttle} seconds")
        log(f"Verbose: {'ON' if verbose else 'OFF'}\n")

        spinner_thread = threading.Thread(target=spinner)
        spinner_thread.start()

        try:
            run_all_checks(args.target, args.safe_mode)
        finally:
            stop_spinner = True
            spinner_thread.join()
            print("\n✅ Scan completed. Report saved to:", report_file)
