<div align="center">

<img src="docs/screenshots/banner.svg" width="100%" alt="APIShield"/>

<br>

[![Version](https://img.shields.io/badge/version-1.0-00d4ff?style=flat-square)]()
[![License](https://img.shields.io/badge/license-MIT-00d4ff?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8+-00d4ff?style=flat-square&logo=python&logoColor=white)]()
[![OWASP](https://img.shields.io/badge/OWASP_API-Top_10_2023-00d4ff?style=flat-square)]()
[![Tests](https://img.shields.io/badge/modules-10-00d4ff?style=flat-square)]()
[![On-Prem](https://img.shields.io/badge/on--prem-deployable-00d4ff?style=flat-square)]()

**API Security Testing Framework — OWASP API Security Top 10 (2023)**

[Quick Start](#quick-start) · [Modules](#test-modules) · [Usage](#usage) · [Reporting](#reporting) · [Architecture](#architecture) · [Contributing](#contributing)

</div>

---

## Overview

APIShield is an open-source API security testing framework that automates detection of the OWASP API Security Top 10 (2023) vulnerability categories. A single Python script (941 lines) runs 10 test modules against any REST API, generating JSON and HTML reports with severity classification and remediation guidance.

### Design Principles

- **Single-file deployment** — 941 lines of Python. No complex installation or infrastructure.
- **Standards-aligned** — Every test maps to a specific OWASP API Security Top 10 (2023) category.
- **On-premises** — Runs entirely on your infrastructure. No data leaves your environment.
- **Authenticated scanning** — Pass Bearer tokens, API keys, or custom headers for authorized testing.
- **Selective execution** — Run all 10 modules or target specific OWASP categories.
- **Actionable output** — Every finding includes severity, risk description, and remediation steps.

---

## Quick Start

```bash
git clone https://github.com/SiteQ8/APIShield.git
cd APIShield
pip install requests

# Full scan
python3 apishield.py -u https://api.example.com

# Authenticated scan
python3 apishield.py -u https://api.example.com -H "Authorization: Bearer TOKEN"

# Specific endpoints
python3 apishield.py -u https://api.example.com -e /users,/orders,/admin

# Specific OWASP tests
python3 apishield.py -u https://api.example.com --tests API1,API4,API8
```

---

## Test Modules

All 10 OWASP API Security Top 10 (2023) categories:

| Module | OWASP ID | Severity | Techniques |
|--------|----------|----------|------------|
| **Broken Object Level Authorization** | API1:2023 | CRITICAL | IDOR via numeric ID increment, UUID substitution, MongoDB ObjectID manipulation, response comparison |
| **Broken Authentication** | API2:2023 | CRITICAL | Weak credential testing (5 common pairs), missing auth on sensitive paths (/admin, /users, /config), token leakage detection |
| **Broken Object Property Level Authorization** | API3:2023 | HIGH | 16 sensitive field signatures (password, token, ssn, api_key, role), mass assignment via property injection |
| **Unrestricted Resource Consumption** | API4:2023 | HIGH | 20-request burst (429 detection), rate limit header check, 100KB payload test, pagination bypass (limit=999999) |
| **Broken Function Level Authorization** | API5:2023 | CRITICAL | 25 admin/debug path probes, HTTP method tampering (GET→DELETE, GET→PUT), privilege escalation detection |
| **Unrestricted Access to Sensitive Flows** | API6:2023 | MEDIUM | 16 business-critical patterns (purchase, checkout, transfer, OTP), CAPTCHA and CSRF token detection |
| **Server Side Request Forgery** | API7:2023 | HIGH | 16 URL parameters tested against 3 internal targets (127.0.0.1, AWS IMDS, GCP/Azure metadata), cloud indicator detection |
| **Security Misconfiguration** | API8:2023 | MEDIUM | CORS origin reflection, 6 security headers, Server/X-Powered-By disclosure, verbose error probing, TRACE/TRACK method detection |
| **Improper Inventory Management** | API9:2023 | MEDIUM | 50+ endpoint discovery (Swagger, OpenAPI, GraphQL, Actuator, .git, .env, /v1-v3, /beta, /staging), concurrent scanning |
| **Unsafe Consumption of APIs** | API10:2023 | HIGH | SQL injection (4), NoSQL (3), XSS (2), SSTI (3), command injection (4), path traversal (2) — via query params and JSON body |

---

## Usage

```
python3 apishield.py -u URL [OPTIONS]

Required:
  -u, --url           Base URL of the target API

Options:
  -e, --endpoints     Comma-separated endpoint paths to test
  -H, --header        Custom HTTP header (repeatable)
  --tests             Specific OWASP tests (e.g., API1,API4,API8)
  --timeout N         Request timeout in seconds (default: 10)
  --no-verify         Skip TLS certificate verification
  --version           Display version number
```

### Examples

```bash
# Full scan with authentication
python3 apishield.py -u https://api.example.com -H "Authorization: Bearer eyJ..."

# API key authentication
python3 apishield.py -u https://api.example.com -H "X-API-Key: sk_live_..."

# Multiple custom headers
python3 apishield.py -u https://api.example.com \
  -H "Authorization: Bearer TOKEN" \
  -H "X-Tenant-ID: acme-corp"

# Test only authentication and rate limiting
python3 apishield.py -u https://api.example.com --tests API2,API4

# Internal staging API (skip TLS)
python3 apishield.py -u https://staging.internal:8443 --no-verify

# Custom endpoints with auth
python3 apishield.py -u https://api.example.com \
  -e /api/v2/users,/api/v2/orders,/api/v2/admin/settings \
  -H "Authorization: Bearer TOKEN"
```

---

## Reporting

Every scan generates two report files in `./apishield_reports/`:

| Format | Contents | Use Case |
|--------|----------|----------|
| **JSON** | Structured results with target, timestamp, per-test findings, severity, remediation | CI/CD integration, SIEM ingestion, GRC platforms, automated pipelines |
| **HTML** | Visual report with color-coded severity, security score, detailed findings | Management review, audit evidence, stakeholder communication |

### Security Score

Score starts at 100% and deducts 5% per vulnerability found. Color-coded in the summary:
- **80-100%** — Well secured
- **60-79%** — Needs improvement
- **Below 60%** — Critical gaps require immediate attention

---

## Architecture

```
apishield.py (941 lines)
├── Session              HTTP client with retry logic, auth, timeout
├── TestBOLA             API1 — Object-level authorization (IDOR)
├── TestBrokenAuth       API2 — Authentication weakness detection
├── TestBOPLA            API3 — Property-level auth (mass assignment)
├── TestResourceConsumption  API4 — Rate limiting, payload size, pagination
├── TestBFLA             API5 — Function-level auth (admin endpoint access)
├── TestSensitiveFlows   API6 — Business flow anti-automation checks
├── TestSSRF             API7 — Server-side request forgery
├── TestMisconfig        API8 — CORS, headers, errors, HTTP methods
├── TestInventory        API9 — Endpoint discovery (50+ paths, concurrent)
├── TestUnsafeConsumption  API10 — Injection (SQL, NoSQL, XSS, SSTI, cmd)
└── Reporter             JSON + HTML generation with severity scoring
```

### How Each Module Works

**API1 (BOLA):** Extracts object IDs from endpoint paths using regex patterns for numeric, UUID, and MongoDB ObjectID formats. Generates alternate IDs and requests resources to detect unauthorized access.

**API2 (Auth):** Sends 5 common credential pairs to discovered authentication endpoints. Tests sensitive paths without authentication headers to detect missing access controls.

**API3 (BOPLA):** Scans response bodies for 16 sensitive field patterns. Sends POST/PUT requests with admin/role fields to detect mass assignment vulnerabilities.

**API4 (Rate Limiting):** Sends 20 rapid sequential requests and checks for 429 responses. Inspects response headers for rate limit indicators. Tests oversized payloads and pagination abuse.

**API5 (BFLA):** Probes 25 common administrative and debug paths with multiple HTTP methods. Tests method tampering by sending destructive methods (DELETE, PUT) to read-only endpoints.

**API7 (SSRF):** Injects internal URLs (localhost, cloud IMDS endpoints) through 16 common URL parameter names. Checks response bodies for cloud metadata indicators.

**API9 (Inventory):** Concurrently scans 50+ paths using ThreadPoolExecutor. Categorizes discovered endpoints as documentation, debug, versioning, or sensitive.

---

## Disclaimer

APIShield performs active security testing including sending injection payloads, authentication probes, and endpoint discovery requests. **Only use against APIs you own or have explicit written authorization to test.** Unauthorized testing may violate applicable laws and regulations.

---

## Contributing

Contributions are accepted for:

- Additional injection payloads and detection signatures
- OpenAPI/Swagger specification parsing for automatic endpoint discovery
- OAuth2 and JWT authentication flow automation
- GraphQL-specific test modules
- CI/CD integration (exit codes, SARIF output format)
- Rate limiting evasion detection improvements

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

MIT License — see [LICENSE](LICENSE).

---

<div align="center">
  <sub>APIShield — API Security Testing Framework</sub><br>
  <sub><a href="https://github.com/SiteQ8">@SiteQ8</a> — Ali AlEnezi</sub><br>
  <sub>OWASP API Security Top 10 (2023)</sub>
</div>
