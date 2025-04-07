# graphql-scanner

## Description

`scan.py` is a Python script that checks a GraphQL endpoint for common vulnerabilities, including introspection, schema misconfigurations, and denial-of-service (DoS)-related issues. It is designed for **educational and authorized security testing only**.

This scanner supports **safe-mode**, **request throttling**, **verbose debug logging**, and generates a **timestamped report file** for offline analysis.

> **⚠️ Disclaimer**: This tool must only be used against systems for which you have **explicit permission**. Unauthorized use is strictly prohibited and may be illegal. Always respect target system policies, and follow responsible disclosure guidelines.

---

## Current Checks

- ✅ Introspection
- ✅ Circular Introspection
- ✅ Deeply Nested Query (optional, skipped in `--safe-mode`)
- ✅ Batch Requests (optional, skipped in `--safe-mode`)
- ✅ Excessive Resource Requests
- ✅ Unlimited Number of Directives
- ✅ Error-Based Enumeration (e.g., suggestion leakage)
- ✅ Authorization Bypass (type-level)
- ✅ Field Suggestion Leakage
- ✅ Rate Limiting Test (optional, skipped in `--safe-mode`)
- ✅ Fake Type Discovery (e.g., `Token`, `Session`, `SecretUser`)
- ✅ Sensitive Field Leak (e.g., `token`, `password` in `User` type)

---

## Installation

Clone the repository:


    git clone https://github.com/davidfortytwo/graphql-scanner
    cd graphql-scanner


# Installation 

Clone repository with:

    git clone https://github.com/davidfortytwo/graphql-scanner

Install dependencies with:

    pip3 install -r requirements

# Usage

Basic scan:

    python scan.py -t http://example.com/graphql

This will run the scanner against the specified endpoint and print out any vulnerabilities that it finds.

Optional Flags:

    Option	Description
    --safe-mode	Avoids checks that could cause server stress (deep nesting, batch, rate limit tests).
    --throttle <sec>	Set delay (in seconds) between each request. Default is 0.5.
    --verbose	Enables debug output, useful for troubleshooting.

Example:

    python3 scan.py -t http://example.com/graphql --safe-mode --throttle 1.0 --verbose

# Output

All output is shown in the terminal with color coding.
A full report is saved to a file: graphql_scan_report_<timestamp>.txt.

Color Coding:

Color	Meaning

    🔴 Red	High/critical issue or clear misconfiguration
    🟢 Green	No vulnerability found
    🔵 Blue	Informational or low severity
    ⚪ White	Evidence, data dumps, verbose messages

Severity Levels:

    Info (Green)
    Low (Blue)
    Medium (Orange)
    High (Red)
    Critical (Violet – reserved for future additions)


## Contributing

    More checks and modules (e.g., mutation introspection, relay abuse) are planned. Feel free to fork and contribute enhancements or bugfixes.


## Legal & Ethical Notice

    This script is provided for educational and ethical hacking use cases only. Do not run it against systems you do not own or have explicit authorization to test. Misuse of this tool can result in criminal charges. The authors take no responsibility for illegal or unethical use.
