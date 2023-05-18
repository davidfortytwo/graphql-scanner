#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: David Espejo (Fortytwo Security)
import argparse
import requests
import json
from termcolor import colored

def check_introspection(url):
    introspection_query = {
        'query': '''{
        __schema {
            types {
                name
            }
        }
    }'''}

    try:
        response = requests.post(url, json=introspection_query)
        response.raise_for_status()
        response_json = response.json()

        if 'data' in response_json and '__schema' in response_json['data']:
            print(colored(f"[!] Introspection is enabled at {url}", "red"))
            print(colored(f"Typical severity: Low", "blue"))
            print("Evidence:", json.dumps(response_json, indent=4))
            return True
        else:
            print(colored(f"[-] Introspection is not enabled at {url}", "green"))
            return False
    except Exception as e:
        print(f"Error during introspection check: {e}")
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

    try:
        response = requests.post(url, json=circular_introspection_query)
        response.raise_for_status()
        response_json = response.json()

        if 'data' in response_json and '__type' in response_json['data']:
            print(colored(f"[!] Circular introspection vulnerability found at {url}", "red"))
            print(colored(f"Typical severity: High", "red"))
            print("Evidence:", json.dumps(response_json, indent=4))
        else:
            print(colored(f"[-] No circular introspection vulnerability found at {url}", "green"))
    except Exception as e:
        print(f"Error during circular introspection check: {e}")
    
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

    try:
        response = requests.post(url, json=resource_query)
        response.raise_for_status()
        response_json = response.json()

        if 'data' in response_json and '__type' in response_json['data']:
            print(colored(f"[!] Excessive resource request vulnerability found at {url}", "red"))
            print(colored(f"Typical severity: High", "red"))
            print("Evidence:", json.dumps(response_json, indent=4))
        else:
            print(colored(f"[-] No excessive resource request vulnerability found at {url}", "green"))
    except Exception as e:
        print(f"Error during resource request check: {e}")
        
def check_zombie_objects(url):
    introspection_query = {
        'query': '''{
        __schema {
            types {
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
            queryType {
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
            mutationType {
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
            subscriptionType {
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
        }
    }'''}

    try:
        response = requests.post(url, json=introspection_query)
        response.raise_for_status()
        response_json = response.json()

        if 'data' in response_json and '__schema' in response_json['data']:
            types = set(type['name'] for type in response_json['data']['__schema']['types'])
            query_types = set(field['type']['name'] for field in response_json['data']['__schema']['queryType']['fields'])
            mutation_types = set(field['type']['name'] for field in response_json['data']['__schema']['mutationType']['fields'])
            subscription_types = set(field['type']['name'] for field in response_json['data']['__schema']['subscriptionType']['fields'])

            zombie_objects = types - query_types - mutation_types - subscription_types

            if zombie_objects:
                print(colored(f"[!] Zombie objects found at {url}", "red"))
                print(colored(f"Typical severity: High", "red"))
                print("Zombie objects:", ', '.join(zombie_objects))
            else:
                print(colored(f"[-] No zombie objects found at {url}", "green"))
        else:
            print(colored(f"[-] Introspection is not enabled at {url}", "green"))
    except Exception as e:
        print(f"Error during zombie objects check: {e}")        

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

    try:
        response = requests.post(url, json=directive_query)
        response.raise_for_status()
        response_json = response.json()

        if 'data' in response_json and '__type' in response_json['data']:
            print(colored(f"[!] Unlimited number of directives vulnerability found at {url}", "red"))
            print(colored(f"Typical severity: Low", "blue"))              
            print("Evidence:", json.dumps(response_json, indent=4))
        else:
            print(colored(f"[-] No unlimited number of directives vulnerability found at {url}", "green"))
    except Exception as e:
        print(f"Error during directive limit check: {e}")

# Add more checks here...

def main(target):
    introspection_enabled = check_introspection(target)
    if introspection_enabled:
        check_circular_introspection(target)
        check_zombie_objects(target)
    check_resource_request(target)
    check_directive_limit(target)
    # Call more checks here...

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check GraphQL endpoint for common vulnerabilities.")
    parser.add_argument('-t', '--target', type=str, required=True, help="Target GraphQL endpoint.")
    args = parser.parse_args()
    main(args.target)
