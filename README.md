# graphql-scanner

# Description

scan.py is a Python script that checks a GraphQL endpoint for common vulnerabilities, including introspection, excessive resource requests, and unlimited number of directives. This script is intended for educational purposes, and should only be used against systems for which you have proper authorization.

Current checks:
* Introspection 
* Excessive resource requests
* Unlimited number of directives

Other checks will be added.

# Installation 

Clone repository with:

  git clone https://github.com/davidfortytwo/graphql-scanner

Install dependencies with:

  pip3 install -r requirements

# Usage

To use the script, you'll need to pass the -t or --target argument with the URL of the GraphQL endpoint you want to scan. Here's an example:

  python scan.py -t http://example.com/graphql

This will run the scanner against the specified endpoint and print out any vulnerabilities that it finds.

# Output

The script color codes its output for easy reading:

- Red: A potential vulnerability was found.
- Green: No vulnerability was found.
- White/Default: Evidence for a found vulnerability.

Remember that not all potential vulnerabilities are actual vulnerabilities. Always confirm any findings manually.