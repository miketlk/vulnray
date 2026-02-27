EMBEDDED_C_GUIDANCE = """
Embedded C constitutions (adapted from VulnLLM-R guidance):
- CWE-121/CWE-125/CWE-787: enforce lower+upper bounds before any buffer read/write.
- CWE-190/CWE-191: validate ranges before arithmetic, allocation sizing, and pointer math.
- CWE-416/CWE-761: reject any access after free; preserve original pointers for free().
- CWE-476: require NULL checks before pointer dereference on all error-prone paths.
- CWE-134/CWE-22/CWE-23: keep format strings and path construction independent of untrusted input.
- CWE-367: avoid check-then-use race windows on shared filesystem or device resources.
- CWE-327/CWE-200: flag weak crypto choices and any key/secret material exposure.
""".strip()
