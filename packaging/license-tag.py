#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# Build the spec's License: value from %cargo_license_summary output.
#
# Usage: packaging/license-tag.py build.log
# Reads the "# <expression>" lines rpmbuild prints in %build (CI's
# "Licenses of the vendored crates" step shows them), splits each on
# top-level AND, lists every term once (MIT first, for rust-peerdup itself),
# and prints the expression to paste into rust-peerdup.spec.

import re
import sys


def top_level_and_terms(expr):
    """Split an SPDX expression on AND outside parentheses."""
    depth = 0
    cur = ""
    parts = []
    for tok in re.split(r"(\(|\)| AND )", expr):
        if tok == "(":
            depth += 1
            cur += tok
        elif tok == ")":
            depth -= 1
            cur += tok
        elif tok == " AND " and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += tok
    parts.append(cur)
    out = []
    for p in parts:
        p = p.strip()
        if p.startswith("(") and p.endswith(")") and p.count("(") == 1:
            p = p[1:-1]
        out.append(p)
    return out


def main(path):
    terms = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.startswith("# "):
                continue
            for t in top_level_and_terms(line[2:].strip()):
                if t and t not in terms:
                    terms.append(t)
    singles = sorted(t for t in terms if " OR " not in t and t != "MIT")
    ors = sorted(t for t in terms if " OR " in t)
    print(" AND ".join(["MIT"] + singles + [f"({t})" for t in ors]))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: license-tag.py BUILD_LOG")
    main(sys.argv[1])
