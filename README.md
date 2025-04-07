# graphql-scanner

## Description

`scan.py` is a Python script that checks a GraphQL endpoint for common vulnerabilities, including introspection, schema misconfigurations, and denial-of-service (DoS)-related issues. It is designed for **educational and authorized security testing only**.

This scanner supports:

    - ✅ **Safe mode** to avoid DoS risks
    - 💤 **Request throttling**
    - 🗂️ **Automatic report generation** (timestamped `.txt` file)
    - 🔐 **Support for session cookies and Bearer tokens**
    - 🧠 **Schema analysis with field classification and depth estimation**
    - 🚨 **Sensitive field detection and live data resolution**
    - 📊 **Schema coverage report with field/complexity metrics**
    - 💬 **Verbose mode for debugging responses and headers**

> **⚠️ Disclaimer**: This tool must only be used against systems for which you have **explicit permission**. Unauthorized use is strictly prohibited and may be illegal. Always respect target system policies, and follow responsible disclosure guidelines.

---

## Current Checks

- ✅ **Introspection Exposure** (`__schema`)
- ✅ **Circular Introspection Abuse** (`__type(name: "Query")`)
- ✅ **Deeply Nested Query Handling** *(optional, skipped in `--safe-mode`)*
- ✅ **Batch Query Processing** *(optional, skipped in `--safe-mode`)*
- ✅ **Excessive Resource Exposure** (`__type(name: "User")`) with:
  - Field type classification (SCALAR, LIST, OBJECT, etc.)
  - Sensitive field heuristics (`token`, `password`, etc.)
  - Depth estimation
- ✅ **Unlimited Directives Enumeration**
- ✅ **Error-Based Enumeration** (e.g., "Did you mean")
- ✅ **Authorization Bypass Detection** (with auth context awareness)
- ✅ **Field Suggestion Leakage**
- ✅ **Rate Limiting Behavior Test** *(optional, skipped in `--safe-mode`)*
- ✅ **Fake/Hidden Type Discovery** (e.g., `Token`, `Session`, `SecretUser`)
- ✅ **Sensitive Field Resolver** — tests if sensitive fields return real data
- ✅ **Schema Coverage Summary** — field count, depth, exposure

---


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
    --cookie "<val>"	Include a session cookie (e.g., 'sessionid=abc123; other=value')
    --bearer <token>	Set a Bearer token for Authorization header

Example:

Run a safe-mode scan with a throttle and debug output:

    python3 scan.py -t http://example.com/graphql --safe-mode --throttle 1.0 --verbose

Run authenticated with a session cookie:

    python scan.py -t https://example.com/graphql --cookie "sessionid=abc123"

Run with a Bearer token:

    python scan.py -t https://example.com/graphql --bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...



# Output

All output is shown in the terminal with color coding.
A full report is saved to a file: graphql_scan_report_<timestamp>.txt.

Color Coding:

    🔴 Red	Confirmed vulnerability or sensitive result
    🟢 Green	No issue / resolved / blocked
    🔵 Blue	Informational or warning
    ⚪ White	Evidence, data dump, or debug info
    🟠 Orange	(Planned for future use — Medium/Caution)


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
