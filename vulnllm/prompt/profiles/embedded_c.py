EMBEDDED_C_GUIDANCE = """
Embedded C review policy:
- Prioritize concrete exploitability over hypothetical missing checks.
- Treat API contracts, caller validation, assertions, and compile-time invariants as first-class evidence.
- Distinguish attacker-controlled inputs from trusted/internal values.
- Prefer "no finding" when vulnerability requires violating explicit caller contracts without breach evidence.
""".strip()
