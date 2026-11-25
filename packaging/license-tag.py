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
lines = [l[2:].strip() for l in open(sys.argv[1]) if l.startswith('# ')]
terms=[]
def add(t):
    t=t.strip()
    if t.startswith('(') and t.endswith(')') and t.count('(')==1: t=t[1:-1]
    if t not in terms: terms.append(t)
for l in lines:
    depth=0; cur=''; parts=[]
    for tk in re.split(r'(\(|\)| AND )', l):
        if tk=='(': depth+=1; cur+=tk
        elif tk==')': depth-=1; cur+=tk
        elif tk==' AND ' and depth==0: parts.append(cur); cur=''
        else: cur+=tk
    parts.append(cur)
    for p in parts: add(p)
add('MIT')
singles=sorted(t for t in terms if ' OR ' not in t and t!='MIT')
ors=sorted(t for t in terms if ' OR ' in t)
print(' AND '.join(['MIT']+singles+[f'({t})' for t in ors]))
