from __future__ import annotations

LANG_EXTENSIONS = {
    "c": {".c", ".h"},
}


def allowed_extensions(languages: list[str]) -> set[str]:
    exts: set[str] = set()
    for lang in languages:
        exts |= LANG_EXTENSIONS.get(lang, set())
    return exts
