#!/usr/bin/env python3
"""Fail when tracked files contain a studied-name denylist token.

The denylist is never committed. Supply it with one of:

* ``CARNOT_STUDIED_NAME_DENYLIST`` — newline- or comma-separated names
* ``CARNOT_STUDIED_NAME_DENYLIST_FILE`` — path to a names file
* ``<root>/.carnot/studied-name-denylist.txt`` — gitignored local file

When no source is configured, the process exits 0 and reports that the check
was skipped. A source that is set but missing, unreadable, or empty exits 2.
Matches are reported as path and line only; the matched text is not printed.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path


def parse_terms(raw: str) -> list[str]:
    terms: list[str] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for part in stripped.split(","):
            term = part.strip()
            if len(term) < 2:
                continue
            key = term.casefold()
            if key in seen:
                continue
            seen.add(key)
            terms.append(term)
    return terms


class DenylistConfigError(Exception):
    """A denylist source was selected but cannot be used. Message has no names."""


def load_terms(root: Path) -> list[str] | None:
    """Return terms, or None when the denylist is absent.

    Whitespace-only ``CARNOT_STUDIED_NAME_DENYLIST`` is treated as unset.
    A non-empty environment value or an explicit file path that yields no
    names, or a file that cannot be read, raises ``DenylistConfigError``.
    """
    env = os.environ.get("CARNOT_STUDIED_NAME_DENYLIST")
    if env is not None and env.strip():
        terms = parse_terms(env)
        if not terms:
            raise DenylistConfigError(
                "studied-name check error: denylist is configured but empty"
            )
        return terms

    file_env = os.environ.get("CARNOT_STUDIED_NAME_DENYLIST_FILE", "").strip()
    if file_env:
        return _require_terms(Path(file_env))

    default = root / ".carnot" / "studied-name-denylist.txt"
    if not default.is_file():
        return None
    return _require_terms(default)


def _require_terms(path: Path) -> list[str]:
    if not path.is_file():
        raise DenylistConfigError(
            "studied-name check error: configured denylist file is missing"
        )
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise DenylistConfigError(
            "studied-name check error: configured denylist file is unreadable"
        ) from exc
    terms = parse_terms(text)
    if not terms:
        raise DenylistConfigError(
            "studied-name check error: configured denylist file is empty"
        )
    return terms


def _left_ok(text: str, index: int) -> bool:
    if index <= 0:
        return True
    prev = text[index - 1]
    if not prev.isalnum():
        return True
    # CamelCase hump: `useToken` starts the term at an uppercase letter.
    return prev.islower() and text[index].isupper()


def _right_ok(text: str, end: int) -> bool:
    if end >= len(text):
        return True
    nxt = text[end]
    if not nxt.isalnum():
        return True
    if nxt.islower() or nxt.isdigit():
        return False
    # Uppercase continues a match only when it starts another CamelCase word
    # (`NameIndex`). An all-caps tail (`README`) does not.
    if end + 1 >= len(text):
        return False
    return text[end + 1].islower()


def term_spans(text: str, term: str) -> list[tuple[int, int]]:
    needle = term.casefold()
    if len(needle) < 2:
        return []
    hay = text.casefold()
    spans: list[tuple[int, int]] = []
    start = 0
    while True:
        index = hay.find(needle, start)
        if index < 0:
            break
        end = index + len(needle)
        if _left_ok(text, index) and _right_ok(text, end):
            spans.append((index, end))
        start = index + 1
    return spans


def tracked_paths(root: Path) -> list[str]:
    proc = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        check=False,
        capture_output=True,
    )
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(err or "git ls-files failed")
    raw = proc.stdout.decode("utf-8", errors="replace")
    paths: list[str] = []
    for piece in raw.split("\0"):
        if not piece:
            continue
        paths.append(piece.replace("\\", "/"))
    return paths


def redact_anywhere(text: str, terms: list[str]) -> str:
    """Strip denylist text from a path even when boundary rules would not match."""
    redacted = text
    for term in sorted(terms, key=len, reverse=True):
        redacted = re.sub(
            re.escape(term), "[redacted]", redacted, flags=re.IGNORECASE
        )
    return redacted


def scan(root: Path, terms: list[str]) -> list[str]:
    hits: list[str] = []
    for rel in tracked_paths(root):
        safe_rel = redact_anywhere(rel, terms)
        if any(term_spans(rel, term) for term in terms):
            hits.append(f"{safe_rel}: denylisted token in tracked path")
        path = root / rel
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            if any(term_spans(line, term) for term in terms):
                hits.append(f"{safe_rel}:{line_no}: denylisted token")
    return hits


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="repository root (default: current directory)",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()

    try:
        terms = load_terms(root)
    except DenylistConfigError as exc:
        print(exc, file=sys.stderr)
        return 2
    except OSError:
        print("studied-name check error: denylist could not be read", file=sys.stderr)
        return 2
    if not terms:
        print("studied-name check skipped: denylist absent")
        return 0

    try:
        hits = scan(root, terms)
    except RuntimeError as exc:
        print(f"studied-name check error: {exc}", file=sys.stderr)
        return 2

    if hits:
        for hit in hits:
            print(hit)
        print(f"studied-name check failed: {len(hits)} hit(s)")
        return 1

    print("studied-name check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
