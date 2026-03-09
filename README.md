<div align="center">

<img src="docs/screenshots/banner.svg" width="100%" alt="APIShield"/>

<br>

[![Version](https://img.shields.io/badge/version-1.0-00d4ff?style=flat-square)]()
[![License](https://img.shields.io/badge/license-MIT-00d4ff?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8+-00d4ff?style=flat-square&logo=python&logoColor=white)]()
[![OWASP](https://img.shields.io/badge/OWASP_API-Top_10_2023-00d4ff?style=flat-square)]()
[![Tests](https://img.shields.io/badge/tests-10-00d4ff?style=flat-square)]()

**API Security Testing Framework — OWASP API Security Top 10 (2023)**

[Quick Start](#quick-start) · [Tests](#test-modules) · [Usage](#usage) · [Reporting](#reporting) · [Contributing](#contributing)

</div>

---

## The Gap

APIs are the #1 attack surface in modern applications. The OWASP API Security Top 10 (2023) is the industry standard for API security — but there is no simple, single-script, open-source tool that tests all 10 categories. Commercial alternatives cost $10,000+/year.

**APIShield fills that gap.** 941 lines of Python. 10 test modules. Zero cloud dependencies. One command.

---

## Quick Start

```bash
git clone https://github.com/SiteQ8/APIShield.git
cd APIShield
pip install requests

# Full scan
python3 apishield.py -u https://api.example.com

# With authentication
python3 apishield.py -u https://api.example.com -H "Authorization: Bearer TOKEN"

# Specific endpoints
python3 apishield.py -u https://api.example.com -e /users,/orders,/admin

# Specific tests only
python3 apishield.py -u https://api.example.com --tests API1,API4,API8
```

---

## Test Modules

All 10 OWASP API Security Top 10 (2023) categories:

| Test | OWASP | Severity | What It Tests |
|------|-------|----------|---------------|
| **API1** | Broken Object Level Authorization | CRITICAL | IDOR — access objects with different IDs (numeric, UUID, ObjectID) |
| **API2** | Broken Authentication | CRITICAL | Weak credentials, missing auth on protected endpoints, token leakage |
| **API3** | Broken Object Property Level Authorization | HIGH | Mass assignment, sensitive field exposure (passwords, keys, roles) |
| **API4** | Unrestricted Resource Consumption | HIGH | Rate limiting absence, large payload acceptance, pagination bypass |
| **API5** | Broken Function Level Authorization | CRITICAL | Admin endpoint access, HTTP method tampering, privilege escalation |
| **API6** | Unrestricted Access to Sensitive Flows | MEDIUM | Missing CAPTCHA/CSRF on business-critical operations |
| **API7** | Server Side Request Forgery (SSRF) | HIGH | URL parameters fetching internal resources (AWS IMDS, localhost) |
| **API8** | Security Misconfiguration | MEDIUM | CORS, missing security headers, server disclosure, verbose errors |
| **API9** | Improper Inventory Management | MEDIUM | Exposed Swagger/OpenAPI, debug endpoints, actuator, old API versions |
| **API10** | Unsafe Consumption of APIs | HIGH | SQL/NoSQL/XSS/SSTI/Command injection via parameters and JSON body |

---

## Usage

```
python3 apishield.py -u URL [OPTIONS]

Required:
  -u, --url           Base URL of the API

Options:
  -e, --endpoints     Comma-separated endpoint paths to test
  -H, --header        Custom header (repeatable)
  --tests             Specific tests (e.g., API1,API4,API8)
  --timeout N         Request timeout in seconds (default: 10)
  --no-verify         Skip TLS certificate verification
  --version           Show version
```

---

## Reporting

Every scan generates two reports in `./apishield_reports/`:

| Format | Contents |
|--------|----------|
| **JSON** | Structured results with all findings, severity, and remediation |
| **HTML** | Visual report with color-coded severity, security score, findings |

Security score: starts at 100%, minus 5% per vulnerability found.

---

## Architecture

```
apishield.py (941 lines)
├── Session — HTTP client with retry, auth, timeout
├── TestBOLA          — API1: Object-level authorization (IDOR)
├── TestBrokenAuth    — API2: Authentication weaknesses
├── TestBOPLA         — API3: Property-level authorization (mass assignment)
├── TestResourceConsumption — API4: Rate limiting, payload size, pagination
├── TestBFLA          — API5: Function-level authorization (admin access)
├── TestSensitiveFlows — API6: Business flow abuse detection
├── TestSSRF          — API7: Server-side request forgery
├── TestMisconfig     — API8: CORS, headers, errors, methods
├── TestInventory     — API9: Endpoint discovery (50+ paths)
├── TestUnsafeConsumption — API10: Injection (SQL, NoSQL, XSS, SSTI, cmd)
└── Reporter — JSON + HTML report generation
```

---

## Disclaimer

APIShield performs active security testing including sending injection payloads and probing for misconfigurations. **Only use against APIs you own or have explicit written authorization to test.** Unauthorized testing may violate applicable laws.

---

## Contributing

Contributions welcome:
- Additional injection payloads and detection signatures
- OpenAPI/Swagger spec parsing for automatic endpoint discovery
- Authentication flow automation (OAuth2, JWT refresh)
- CI/CD integration (exit codes, SARIF output)
- GraphQL-specific test modules

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">
  <sub>APIShield — API Security Testing Framework</sub><br>
  <sub><a href="https://github.com/SiteQ8">@SiteQ8</a> — Ali AlEnezi</sub><br>
  <sub>OWASP API Security Top 10 (2023) — 941 lines — Zero dependencies beyond requests</sub>
</div>
