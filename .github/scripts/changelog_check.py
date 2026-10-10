"""Fail when CHANGELOG.md breaks the Keep-a-Changelog contract (AGENTS.md §9).

Checks, per release section: the `## [X.Y.Z] - YYYY-MM-DD` heading carries
a real calendar date (`[Unreleased]` carries none and stays first); every
section has a matching `[X.Y.Z]:` link definition and vice versa; link
definitions ascend in file order and each points at its own `vX.Y.Z` tag;
release sections descend newest-first with no duplicates; `###` headings
follow the canonical order (Added, Changed, Deprecated, Removed, Fixed,
Performance, Security) with at most one block each; release sections are
never empty. Content rules (tense, prefixes, rationale) stay human review.

Exit codes: 0 = contract holds, 1 = any violation (each printed as
`path:line: message`).

Usage: changelog_check.py [PATH]  (default CHANGELOG.md)
"""

import itertools
import re
import sys
from datetime import date

CANON = ["Added", "Changed", "Deprecated", "Removed", "Fixed", "Performance", "Security"]
SEC_RE = re.compile(r"^## \[([^\]]+)\](?: - (\d{4}-\d{2}-\d{2}))?\s*$")
HEAD_RE = re.compile(r"^### (\S+)\s*$")
LINK_RE = re.compile(r"^\[(\d+\.\d+\.\d+)\]:\s*(\S+)\s*$")


def parse_version(text):
    return tuple(int(part) for part in text.split("."))


def main(argv):
    path = argv[1] if len(argv) > 1 else "CHANGELOG.md"
    with open(path) as f:
        lines = f.read().splitlines()
    errs = []

    def err(lineno, msg):
        errs.append(f"{path}:{lineno}: {msg}")

    sections = []
    links = []
    current = None
    for lineno, line in enumerate(lines, start=1):
        match = SEC_RE.match(line)
        if match:
            current = {"name": match.group(1), "line": lineno, "date": match.group(2), "heads": []}
            sections.append(current)
            continue
        match = HEAD_RE.match(line)
        if match:
            if current is None:
                err(lineno, f"heading outside any section: {match.group(1)}")
            else:
                current["heads"].append((match.group(1), lineno))
            continue
        match = LINK_RE.match(line)
        if match:
            links.append({"version": match.group(1), "url": match.group(2), "line": lineno})

    if not sections or sections[0]["name"] != "Unreleased":
        err(sections[0]["line"] if sections else 1, "first section must be ## [Unreleased]")
    seen_sections = set()
    releases = []
    for section in sections:
        name = section["name"]
        if name in seen_sections:
            err(section["line"], f"duplicate section: [{name}]")
        seen_sections.add(name)
        last = -1
        for head, hline in section["heads"]:
            if head not in CANON:
                err(hline, f"unknown heading ### {head} (canonical: {', '.join(CANON)})")
                continue
            if CANON.index(head) <= last:
                err(hline, f"### {head} out of canonical order or duplicated")
            last = CANON.index(head)
        if name == "Unreleased":
            if section["date"] is not None:
                err(section["line"], "[Unreleased] must not carry a date")
            continue
        try:
            version = parse_version(name)
            if len(version) != 3:
                raise ValueError
        except ValueError:
            err(section["line"], f"not a version section: [{name}]")
            continue
        releases.append((version, section))
        if section["date"] is None:
            err(section["line"], f"release [{name}] misses its date")
        else:
            try:
                date.fromisoformat(section["date"])
            except ValueError:
                err(section["line"], f"release [{name}] has no real calendar date")
        if not section["heads"]:
            err(section["line"], f"release [{name}] has no ### block")
    for (prev, _), (version, section) in itertools.pairwise(releases):
        if not prev > version:
            err(section["line"], "release sections must descend newest-first")

    seen_links = set()
    for link in links:
        if link["version"] in seen_links:
            err(link["line"], f"duplicate link: [{link['version']}]:")
        seen_links.add(link["version"])
        if not link["url"].endswith(f"/v{link['version']}"):
            err(link["line"], f"link [{link['version']}] does not point at its v{link['version']} tag")
    ordered = [link["version"] for link in links]
    if ordered != sorted(ordered, key=parse_version):
        err(links[0]["line"], "link definitions must ascend oldest-first")
    release_names = {".".join(str(n) for n in v) for v, _ in releases}
    for link in links:
        if link["version"] not in release_names:
            err(link["line"], f"link without section: [{link['version']}]:")
    for version, section in releases:
        name = ".".join(str(n) for n in version)
        if name not in seen_links:
            err(section["line"], f"section without link: [{name}]")

    if errs:
        print("\n".join(errs))
        return 1
    print(f"changelog ok: {len(sections)} sections, {len(links)} links")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
