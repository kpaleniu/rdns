#!/usr/bin/env python3
"""Count comment blocks over the caps in CLAUDE.md "Writing comments".

`//`: at most 2 lines. `///`: one paragraph of at most 8 lines, or a summary
of at most 2 then one paragraph of at most 6. `//!` is exempt; fenced code and
table rows count toward neither. Test code is a `tests/` or `benches/` file, or anything after
a `#[cfg(test)]` that opens a `mod`.

    python tools/comment_caps.py            # counts per crate and region
    python tools/comment_caps.py --list     # every block over, file:line
"""

import collections
import re
import subprocess
import sys

LINE_CAP = 2
SUMMARY_CAP = 2
PARAGRAPH_CAP = 6
TABLE = re.compile(r"^\|.*\|$")


def kind(line):
    s = line.lstrip()
    if s.startswith("//!"):
        return "mod"
    if s.startswith("///") and not s.startswith("////"):
        return "doc"
    if s.startswith("//"):
        return "line"
    return None


def text(line):
    s = line.lstrip()
    return (s[3:] if s[:3] in ("///", "//!") else s[2:]).strip()


def counted(body):
    """The lines a cap applies to: blank lines kept, fences and tables not."""
    out, fence = [], False
    for b in body:
        if b.startswith("```"):
            fence = not fence
            out.append(None)
        elif fence or TABLE.match(b):
            out.append(None)
        else:
            out.append(b)
    return out


def line_over(body):
    return len([b for b in counted(body) if b is not None]) > LINE_CAP


def doc_over(body):
    paras, cur = [], 0
    for b in counted(body):
        if b:
            cur += 1
        elif cur:
            paras.append(cur)
            cur = 0
    if cur:
        paras.append(cur)
    if not paras:
        return False
    if len(paras) == 1:
        return paras[0] > SUMMARY_CAP + PARAGRAPH_CAP
    return len(paras) > 2 or paras[0] > SUMMARY_CAP or paras[1] > PARAGRAPH_CAP


def opens_test_mod(lines, i):
    if lines[i].strip() != "#[cfg(test)]":
        return False
    for nxt in lines[i + 1 :]:
        s = nxt.strip()
        if s.startswith("#["):
            continue
        return bool(re.match(r"(pub(\(\w+\))? )?mod \w+", s))
    return False


def blocks(path):
    lines = open(path, encoding="utf-8").read().split("\n")
    parts = path.split("/")
    test = "tests" in parts[:-1] or "benches" in parts[:-1]
    i = 0
    while i < len(lines):
        if not test and opens_test_mod(lines, i):
            test = True
        k = kind(lines[i])
        if k is None:
            i += 1
            continue
        j = i
        while j < len(lines) and kind(lines[j]) == k:
            j += 1
        yield k, i + 1, [text(l) for l in lines[i:j]], test
        i = j


def main():
    listing = "--list" in sys.argv[1:]
    files = subprocess.run(
        ["git", "ls-files", "*.rs"], capture_output=True, text=True, check=True
    ).stdout.split()
    total = collections.Counter()
    over = collections.Counter()
    for path in files:
        crate = path.split("/")[0]
        for k, line, body, test in blocks(path):
            if k == "mod":
                continue
            region = "test" if test else "code"
            total[(crate, region, k)] += 1
            if (line_over if k == "line" else doc_over)(body):
                over[(crate, region, k)] += 1
                if listing:
                    print(f"{path}:{line}\t{k}\t{region}\t{len(body)}")
    if listing:
        return
    print(f"{'crate':<16}{'region':<6}{'//':>12}{'///':>12}")
    for crate, region in sorted({(c, r) for c, r, _ in total}):
        cells = [
            f"{over[(crate, region, k)]}/{total[(crate, region, k)]}"
            for k in ("line", "doc")
        ]
        print(f"{crate:<16}{region:<6}{cells[0]:>12}{cells[1]:>12}")
    for region in ("code", "test"):
        n = sum(v for (c, r, k), v in over.items() if r == region)
        print(f"over, {region}: {n}")


if __name__ == "__main__":
    main()
