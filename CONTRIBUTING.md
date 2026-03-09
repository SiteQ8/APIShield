# Contributing to APIShield

## Adding Tests
1. Create a class following the TestXxx pattern
2. Implement static `run(session, endpoints)` method
3. Return results dict with test, name, severity, findings
4. Add to `ALL_TESTS` dict in `main()`

## Adding Payloads
Add to the relevant test class's payload lists. Include detection indicators.

## Code Standards
- Python 3.8+ compatible
- Single-file architecture (apishield.py)
- Use `session.request()` for all HTTP calls
- Include remediation advice in every finding
