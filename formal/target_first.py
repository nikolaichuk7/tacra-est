#!/usr/bin/env python3
"""Rewrite the generated models so that every hashed tuple binds the Target before the server
identity, the order of TACRA master 912bd50 (30 September 2026), and nothing else changes.

The models hash a tuple such as h((n, srv, tgt, csr)) in the Attester and h((n, id, tgt, csr)) in
the server. This script swaps the identity (srv, sid, id) with the tgt that follows it inside every
h((...)), writes the result to a directory, and reports each rewrite. Running ProVerif on both
sets and comparing the RESULT lines shows whether the order matters to the analysis.

    python3 gen.py && python3 target_first.py <outdir>
"""
import pathlib
import re
import sys

IDENTITIES = {"srv", "sid", "id"}


def split_top(s):
    parts, depth, cur = [], 0, ""
    for ch in s:
        if ch == "," and depth == 0:
            parts.append(cur.strip()); cur = ""; continue
        depth += ch == "("; depth -= ch == ")"
        cur += ch
    parts.append(cur.strip())
    return parts


def rewrite(text):
    out, i, n = [], 0, 0
    while True:
        j = text.find("h((", i)
        if j < 0:
            out.append(text[i:]); break
        k, depth = j + 3, 1
        while depth:                      # find the ")" that closes the tuple opened by "(("
            depth += text[k] == "("; depth -= text[k] == ")"; k += 1
        inner = text[j + 3:k - 1]
        parts = split_top(inner)
        for a in range(len(parts) - 1):
            if parts[a] in IDENTITIES and parts[a + 1] == "tgt":
                parts[a], parts[a + 1] = parts[a + 1], parts[a]; n += 1; break
        out.append(text[i:j] + "h((" + ", ".join(parts) + ")"); i = k
    return "".join(out), n


def main(outdir):
    out = pathlib.Path(outdir); out.mkdir(parents=True, exist_ok=True)
    for f in sorted(pathlib.Path(".").glob("*.pv")):
        text, n = rewrite(f.read_text())
        (out / f.name).write_text(text)
        print("%-52s %d tuple(s) rewritten" % (f.name, n))


if __name__ == "__main__":
    main(sys.argv[1])
