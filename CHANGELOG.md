# Changelog

## [1.0.0] - 2026-03-09

### Added
- 10 OWASP API Security Top 10 (2023) test modules
- API1: BOLA/IDOR testing (numeric, UUID, ObjectID)
- API2: Broken authentication (weak creds, missing auth)
- API3: Mass assignment, sensitive field exposure
- API4: Rate limiting, payload size, pagination abuse
- API5: Admin endpoint discovery, HTTP method tampering
- API6: Sensitive business flow detection
- API7: SSRF testing (AWS/GCP/Azure IMDS, localhost)
- API8: CORS, security headers, server disclosure, verbose errors
- API9: Endpoint inventory (50+ discovery paths)
- API10: Injection (SQL, NoSQL, XSS, SSTI, command, path traversal)
- JSON and HTML report generation with security scoring
- Custom header and endpoint support
- Concurrent endpoint discovery
- Session management with retry logic
