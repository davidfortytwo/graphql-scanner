#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: David Espejo (Fortytwo Security)
import argparse
import requests
import json
from termcolor import colored

def send_query(url, query):
    headers = {'Content-Type': 'application/json'}
    try:
        response = requests.post(url, json=query, headers=headers, timeout=10)
        response.raise_for_status()
        if 'application/json' in response.headers.get('Content-Type', ''):
            return response.json()
        else:
            print(colored(f"[!] Unexpected Content-Type received from {url}", "yellow"))
            return None
    except requests.exceptions.RequestException as e:
        print(colored(f"[!] HTTP error occurred: {e}", "red"))
        return None

def check_introspection(url):
    introspection_query = {
        'query': '''{
        __schema {
            types {
                name
            }
        }
    }'''}
    response_json = send_query(url, introspection_query)
    if response_json and 'data' in response_json and '__schema' in response_json['data']:
        print(colored(f"[!] Introspection is enabled at {url}", "red"))
        print(colored(f"Typical severity: Low", "blue"))
        print("Evidence:", json.dumps(response_json, indent=4))
        return True
    else:
        print(colored(f"[-] Introspection is not enabled at {url}", "green"))
        return False

def check_circular_introspection(url):
    circular_introspection_query = {
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
    response_json = send_query(url, circular_introspection_query)
    if response_json and 'data' in response_json and '__type' in response_json['data']:
        print(colored(f"[!] Circular introspection vulnerability found at {url}", "red"))
        print(colored(f"Typical severity: High", "red"))
        print("Evidence:", json.dumps(response_json, indent=4))
    else:
        print(colored(f"[-] No circular introspection vulnerability found at {url}", "green"))

def check_resource_request(url):
    resource_query = {
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
        }'''}
    response_json = send_query(url, resource_query)
    if response_json and 'data' in response_json and '__type' in response_json['data']:
        print(colored(f"[!] Excessive resource request vulnerability found at {url}", "red"))
        print(colored(f"Typical severity: High", "red"))
        print("Evidence:", json.dumps(response_json, indent=4))
    else:
        print(colored(f"[-] No excessive resource request vulnerability found at {url}", "green"))

def check_directive_limit(url):
    directive_query = {
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
        }'''}
    response_json = send_query(url, directive_query)
    if response_json and 'data' in response_json and '__type' in response_json['data']:
        print(colored(f"[!] Unlimited number of directives vulnerability found at {url}", "red"))
        print(colored(f"Typical severity: Low", "blue"))
        print("Evidence:", json.dumps(response_json, indent=4))
    else:
        print(colored(f"[-] No unlimited number of directives vulnerability found at {url}", "green"))

def check_deeply_nested_query(url):
    deeply_nested_query = {
        'query': '{ a1: __schema { queryType { name, fields { name, type { name, fields { name, type { name } } } } } } }'
    }
    response_json = send_query(url, deeply_nested_query)
    if response_json and 'data' in response_json:
        print(colored(f"[!] Server responds to deeply nested queries at {url}. Possible DoS vulnerability.", "red"))
    else:
        print(colored(f"[-] No issues with deeply nested queries found at {url}.", "green"))

def check_batch_requests(url):
    batch_query = [{'query': '{ __schema { types { name } } }'}] * 10  # Adjust the batch size as needed
    response_json = send_query(url, batch_query)
    if response_json:
        print(colored(f"[!] Server allows batch requests at {url}. May lead to DoS if abused.", "red"))
    else:
        print(colored(f"[-] No batch request vulnerability found at {url}.", "green"))

def main(target):
    print("Starting checks for GraphQL endpoint at:", target)
    if check_introspection(target):
        check_circular_introspection(target)
        check_deeply_nested_query(target)
        check_batch_requests(target)
    check_resource_request(target)
    check_directive_limit(target)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check GraphQL endpoint for common vulnerabilities.")
    parser.add_argument('-t', '--target', type=str, required=True, help="Target GraphQL endpoint.")
    args = parser.parse_args()
    main(args.target)
