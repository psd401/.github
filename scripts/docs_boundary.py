# ABOUTME: The security-scan docs check: restricted network detail stays in docs/restricted/, and Markdown images live in the repo.
# ABOUTME: psd-dev-standards standards/22 rule 3 and rule 16 / Part E (CIO decision 2026-11-25). Stdlib only; never prints a matched value.
"""Docs boundary check.

Usage: python3 -I docs_boundary.py REPO [--base SHA] [--domain DOMAIN]...

Reads every file git tracks in REPO and reports:

  restricted  a private IPv4 address (RFC 1918), a private or link-local
              IPv6 address, a MAC address, or a hostname in a --domain, in any
              text file outside docs/restricted/ (standards/22 Part E: restricted
              detail lives in docs/restricted/ and nowhere else; tests and
              fixtures use made-up values such as RFC 5737 192.0.2.0/24)
  wiki-ignore docs/restricted/ exists but .openwikiignore doesn't list it
  image       a Markdown image whose source is an outside URL (standards/22
              rule 3: an image lives with the document that uses it). Status
              badges (img.shields.io, badgen.net, .../badge.svg) are exempt.

With --base, only findings on lines added since BASE fail (exit 1): a pull
request can't add restricted detail or an outside image, and a repo isn't
failed for what it held before this check existed. Findings elsewhere are
printed as warnings with a count. The wiki-ignore finding always fails, since
the fix is one line. Without --base every finding is a warning (exit 0).

Not checked for restricted detail: Terraform and HCL files (*.tf, *.tf.json,
*.tfvars, *.hcl), which standards/22 rule 20 says hold a system's intended
configuration, CIDR blocks included; and any line carrying the marker
`docs-boundary: allow` (for a test of a redactor that must see a private
range). The marker is visible in review, so every use is a reviewed choice.

A finding names the file, line and kind, never the value.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

RESTRICTED_DIR = "docs/restricted/"
WIKI_IGNORE = ".openwikiignore"
MARKDOWN = (".md", ".markdown", ".mdx")
MAX_BYTES = 1_000_000
MAX_WARNINGS = 20
IAC = (".tf", ".tf.json", ".tfvars", ".hcl")
ALLOW = "docs-boundary: allow"
# .openwikiignore lines that cover docs/restricted/ (the folder itself or all of docs/).
IGNORE_ENTRIES = {f"{d}{s}" for d in ("docs/restricted", "docs") for s in ("", "/", "/*", "/**")}

# The same patterns as psd401/netchange's boundary check (netchange_profile.py).
PRIVATE_V4 = re.compile(
    r"(?<![\d.])(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}(?![\d.]*\d)")
PRIVATE_V6 = re.compile(
    r"(?<![0-9A-Fa-f:])(?:f[cd][0-9a-f]{2}|fe[89ab][0-9a-f]):(?:[0-9a-f]*:)+[0-9a-f]*(?![0-9A-Fa-f:])",
    re.IGNORECASE)
MAC_DOTTED = re.compile(r"(?<![0-9A-Fa-f.])(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}(?![0-9A-Fa-f.])")
MAC = re.compile(r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])")

MD_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*<?(https?://[^)\s>]+)")
HTML_IMAGE = re.compile(r"<img\b[^>]*\bsrc\s*=\s*[\"']?(https?://[^\"'\s>]+)", re.IGNORECASE)
BADGE = re.compile(r"^https?://(?:img\.shields\.io|badgen\.net|[^/]+/[^?#]*badge[^/?#]*\.svg)", re.IGNORECASE)


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          capture_output=True, text=True).stdout


def tracked(repo: Path) -> list[str]:
    return [p for p in git(repo, "ls-files", "-z").split("\0") if p]


def added_lines(repo: Path, base: str) -> dict[str, set[int]]:
    """File -> line numbers added since base (merge-base diff, renames followed)."""
    out: dict[str, set[int]] = {}
    current = None
    for line in git(repo, "diff", "--unified=0", "--no-color", "-M", f"{base}...HEAD").splitlines():
        if line.startswith("+++ "):
            path = line[4:]
            current = path[2:] if path.startswith("b/") else None
            if current is not None:
                out.setdefault(current, set())
        elif line.startswith("@@") and current is not None:
            m = re.search(r"\+(\d+)(?:,(\d+))?", line)
            start, count = int(m.group(1)), int(m.group(2) or "1")
            out[current].update(range(start, start + count))
    return out


def read_text(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) > MAX_BYTES or b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def wiki_ignores_restricted(repo: Path) -> bool:
    f = repo / WIKI_IGNORE
    if not f.is_file():
        return False
    for raw in f.read_text(encoding="utf-8", errors="replace").splitlines():
        entry = raw.strip().lstrip("/")
        if entry in IGNORE_ENTRIES:
            return True
    return False


def findings(repo: Path, domains: list[str]) -> list[tuple[str, int, str]]:
    """(file, line, kind) for every finding; line 0 for a whole-repo finding."""
    hosts = [re.compile(r"(?<![@\w.-])[\w-]+(?:\.[\w-]+)*\." + re.escape(d) + r"\b", re.IGNORECASE)
             for d in domains]
    out: list[tuple[str, int, str]] = []
    files = tracked(repo)
    if any(p.startswith(RESTRICTED_DIR) for p in files) and not wiki_ignores_restricted(repo):
        out.append((WIKI_IGNORE, 0, "wiki-ignore"))
    for rel in files:
        text = read_text(repo / rel)
        if text is None:
            continue
        restricted = rel.startswith(RESTRICTED_DIR) or rel.lower().endswith(IAC)
        markdown = rel.lower().endswith(MARKDOWN)
        for n, line in enumerate(text.splitlines(), 1):
            if not restricted and ALLOW not in line and (PRIVATE_V4.search(line) or PRIVATE_V6.search(line)
                                   or MAC.search(line) or MAC_DOTTED.search(line)
                                   or any(h.search(line) for h in hosts)):
                out.append((rel, n, "restricted"))
            if markdown:
                for url in MD_IMAGE.findall(line) + HTML_IMAGE.findall(line):
                    if not BADGE.match(url):
                        out.append((rel, n, "image"))
                        break
    return out


MESSAGE = {
    "restricted": "restricted network detail (private address, MAC or internal hostname) outside docs/restricted/; "
                  "move it there or use a made-up value such as 192.0.2.10 (standards/22 Part E)",
    "wiki-ignore": "docs/restricted/ exists but .openwikiignore doesn't list it (standards/22 Part E)",
    "image": "Markdown image from an outside URL; commit the image next to the document "
             "and use a relative path (standards/22 rule 3)",
}


def main(argv: list[str]) -> int:
    args = list(argv)
    if not args:
        print(__doc__.split("\n\n")[1])
        return 2
    repo, base, domains = Path(args.pop(0)), None, []
    while args:
        flag = args.pop(0)
        if flag == "--base" and args:
            base = args.pop(0)
        elif flag == "--domain" and args:
            domains.append(args.pop(0))
        else:
            print(f"unknown argument: {flag}")
            return 2
    found = findings(repo, domains)
    added = added_lines(repo, base) if base else {}
    failing = [f for f in found if base and (f[2] == "wiki-ignore" or f[1] in added.get(f[0], ()))]
    rest = [f for f in found if f not in failing]
    for rel, n, kind in failing:
        loc = f"file={rel}" + (f",line={n}" if n else "")
        print(f"::error {loc}::{MESSAGE[kind]}")
    for rel, n, kind in rest[:MAX_WARNINGS]:
        loc = f"file={rel}" + (f",line={n}" if n else "")
        print(f"::warning {loc}::{MESSAGE[kind]} (already in the repo; not failing this run)")
    counts = {k: sum(1 for f in found if f[2] == k) for k in MESSAGE}
    print(f"docs boundary: {len(failing)} failing, {len(rest)} existing "
          f"(restricted {counts['restricted']}, image {counts['image']}, wiki-ignore {counts['wiki-ignore']})")
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
