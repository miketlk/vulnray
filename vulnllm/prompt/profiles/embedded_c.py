EMBEDDED_C_GUIDANCE = """
Embedded C review policy:
- Prioritize concrete sinks over speculative reasoning.
- Respect caller contracts and assertions when visible.
- High-signal sinks must not be missed: strcpy/strcat/sprintf to fixed buffers; untrusted file paths to filesystem APIs.
""".strip()
