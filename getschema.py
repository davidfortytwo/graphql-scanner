#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: David Espejo (Fortytwo Security) + Techno Guardian Enhancements

import argparse
import requests
import json
import sys

FULL_INTROSPECTION_QUERY = """
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
          }
        }
      }
    }
  }
}
"""

MINIMAL_INTROSPECTION_QUERY = """
{
  __schema {
    types { name }
  }
}
"""

def fetch_introspection_schema(url, headers, minimal=False):
    query = {
        "query": MINIMAL_INTROSPECTION_QUERY if minimal else FULL_INTROSPECTION_QUERY
    }
    response = requests.post(url, headers=headers, json=query, timeout=10)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to fetch schema: {response.status_code} - {response.text[:200]}")

def main(args):
    headers = {'Content-Type': 'application/json'}
    if args.cookie:
        headers['Cookie'] = args.cookie
    if args.bearer:
        headers['Authorization'] = f"Bearer {args.bearer}"

    try:
        schema = fetch_introspection_schema(args.target, headers, args.minimal)
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(schema, f, indent=2)
            print(f"[✓] Schema saved to: {args.output}")
        else:
            print(json.dumps(schema, indent=2))
    except Exception as e:
        print(f"[!] Error fetching schema: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch GraphQL schema via introspection.")
    parser.add_argument('-t', '--target', type=str, required=True, help="Target GraphQL API endpoint.")
    parser.add_argument('--cookie', type=str, help="Optional Cookie string.")
    parser.add_argument('--bearer', type=str, help="Optional Bearer token.")
    parser.add_argument('--output', type=str, help="Save result to file.")
    parser.add_argument('--minimal', action='store_true', help="Use minimal introspection query.")
    args = parser.parse_args()
    main(args)
