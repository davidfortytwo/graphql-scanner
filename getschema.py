#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: David Espejo (Fortytwo Security)
import argparse
import requests
import json

def fetch_introspection_schema(url):
    headers = {'Content-Type': 'application/json'}
    query = {
        "query": """
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                    ...FullType
                }
                directives {
                    name
                    description
                    locations
                    args {
                        ...InputValue
                    }
                }
            }
        }

        fragment FullType on __Type {
            kind
            name
            description
            fields(includeDeprecated: true) {
                name
                description
                args {
                    ...InputValue
                }
                type {
                    ...TypeRef
                }
                isDeprecated
                deprecationReason
            }
            inputFields {
                ...InputValue
            }
            interfaces {
                ...TypeRef
            }
            enumValues(includeDeprecated: true) {
                name
                description
                isDeprecated
                deprecationReason
            }
            possibleTypes {
                ...TypeRef
            }
        }

        fragment InputValue on __InputValue {
            name
            description
            type { ...TypeRef }
            defaultValue
        }

        fragment TypeRef on __Type {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                            ofType {
                                kind
                                name
                                ofType {
                                    kind
                                    name
                                }
                            }
                        }
                    }
                }
            }
        }
        """
    }
    response = requests.post(url, headers=headers, json=query)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to fetch schema: {response.status_code} - {response.text}")

def main(target):
    try:
        schema = fetch_introspection_schema(target)
        print(json.dumps(schema, indent=2))
    except Exception as e:
        print(f"Error fetching schema: {str(e)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch GraphQL API schema via introspection.")
    parser.add_argument('-t', '--target', type=str, required=True, help="Target GraphQL API endpoint.")
    args = parser.parse_args()
    main(args.target)
