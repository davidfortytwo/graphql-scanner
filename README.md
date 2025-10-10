# graphql-scanner

## Description

**GraphQL-scanner** checks a GraphQL endpoint for common weaknesses, including introspection exposure, schema misconfigurations, transport/perimeter issues, and safe resource-pressure signals. It uses safe defaults (no havoc), verifies findings with a reproducible `curl` command, and persists evidence only for verified findings.

> **⚠️ Authorized testing only.** Use this tool only against systems where you have explicit permission.

---

## Key Features

- ✅ **Safe defaults**: full suite designed to avoid DoS (moderate sizes, single requests for verification).  
- ✅ **Verification-first reporting**: each finding includes a reproducible `curl` (`verify_curl`) and is only recorded if verification passes smart triage.  
- ✅ **Evidence artifacts**: JSON and TXT per finding in `./evidence/`, severity-prefixed file names.  
- ✅ **Robust HTTP helpers**: JSON, `application/x-www-form-urlencoded` POSTs, and GET probing.  
- ✅ **Content-type aware parsing** and latency capture.  
- ✅ **Colorized terminal output** + optional JSON summary to stdout.

---

## Checks Performed

### Schema / Introspection
- Introspection enabled (`__schema`)  
- Circular introspection (`__type(name:"Query")` with nested `ofType`)  
- Introspection blocklist bypass probes (aliases / fragments / variables)  
- Deprecated field enumeration (`includeDeprecated: true`)  
- Suggestive error leakage (“Did you mean …”)

### Transport / Perimeter Controls
- GET method enabled for GraphQL  
- POST `application/x-www-form-urlencoded` acceptance (potential CSRF surface)  
- CORS configuration (e.g., `*` with credentials)  
- Stack trace / exception leakage (error detail exposure)

### Resource-Pressure (safe signals, not DoS)
- Alias pressure (shallow complexity) (~50 aliases)  
- Fragment explosion (light) (~50 fragments)  
- Deep query handling (depth limit) (depth ~6)  
- Batching behavior & isolation (JSON array payload, ~12 ops)  
- Alias overloading (≥110) — safe single request, latency observed  
- Field duplication (same field ×500) — safe single request  
- Directive overloading (duplicate `@include` ×60) — safe single request

### Feature Surfaces / Dev UI
- Support for `@defer` / `@stream`  
- Developer UI exposure (GraphiQL / Playground / Altair)

### Resource Enumeration
- Excessive resource request for a target type (default: `User`)  
- Directive enumeration (names, locations, args)

> **Note:** Findings the server clearly mitigates (e.g., explicit complexity/depth limits, batch “not supported”, WAF blocks) are treated as **non-findings** and are not persisted.

---

## Installation

```bash
git clone https://github.com/davidfortytwo/graphql-scanner
cd graphql-scanner
pip3 install -r requirements
```

---

## Usage

### Basic scan

```bash
python3 scan.py -t https://example.com/graphql
```

### With headers (Bearer token or cookie)

```bash
python3 scan.py -t https://example.com/graphql \
  -H "Authorization: Bearer <token>" \
  -H "Cookie: sessionid=abc123"
```

### Insecure TLS (staging / self-signed)

```bash
python3 scan.py -t https://staging.local/graphql --insecure
```

### Custom timeout + JSON summary

```bash
python3 scan.py -t https://example.com/graphql --timeout 20 --json
```

---

## Command-Line Options

| Option | Description |
|---|---|
| `-t, --target <url>` | **Required.** Target GraphQL POST endpoint. |
| `-H, --header "Name: Value"` | Extra header (repeatable). Useful for `Authorization`, `Cookie`, etc. |
| `--insecure` | Disable TLS verification (testing only). |
| `--timeout <sec>` | Per-request timeout (default: 12). |
| `--json` | Print final findings as JSON to stdout (in addition to evidence files). |

---

## Output & Evidence

- Terminal output is **colorized** with quick pass/fail signals and timing.  
- Verified findings are persisted to `./evidence/` as:  
  - `1-HIGH-<slug>-<idx>.json` / `.txt`  
  - `2-MEDIUM-<slug>-<idx>.json` / `.txt`  
  - `3-LOW-<slug>-<idx>.json` / `.txt`

Each evidence file includes:
- Metadata (HTTP status, latency, content type)  
- Sanitized fragment/evidence (errors, schema sample, etc.)  
- `verify_curl`: a ready-to-run, heredoc-based `curl` reproducer  
- Raw JSON (pretty-printed when applicable)

> INFO items are printed to the console for context but not written to evidence.

---

## Severity Model

- **HIGH / MEDIUM / LOW**: persisted only if verification passes.  
- **INFO**: contextual breadcrumbs (not persisted).  

Smart triage rejects verified output that indicates WAF blocks or explicit mitigations (e.g., “maximum query complexity”, “depth limit”, “batching not supported”).

---

## Safety

- The suite uses single requests for pressure tests, moderate sizes, and caps on depth/aliases/fragments to avoid service disruption.  
- No parallel flooding; no intentional DoS.  
- If the target returns clear mitigation messages or WAF blocks, the item is treated as **non-finding**.

---

## Contributing

Planned enhancements include mutation abuse probes, Relay-specific checks, persisted query hardening, and more nuanced cost modeling. PRs are welcome — tests and reproducible evidence payloads appreciated.

---

## Legal & Ethical Notice

This tool is for **educational and authorized security testing** only. Do not target systems without explicit permission. Misuse can be illegal. The authors disclaim liability for improper use.
