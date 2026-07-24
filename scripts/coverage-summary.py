#!/usr/bin/env python3
"""Summarize sb-cover's coverage/cover-index.html as a markdown table.

Prints per-source-file expression/branch coverage and an overall figure for the
library sources (the src/ tree), so it can be appended to $GITHUB_STEP_SUMMARY.
"""
import html
import re
import sys

INDEX = "coverage/cover-index.html"


def cells(row):
    raw = re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", row, re.S)
    return [re.sub("<.*?>", "", html.unescape(c)).strip() for c in raw]


def main():
    try:
        text = open(INDEX).read()
    except OSError as e:
        print(f"no coverage report: {e}")
        return 1

    section = None            # "src" | "test" | None
    rows = []                 # (name, expr_cov, expr_tot, branch_str)
    src_cov = src_tot = 0

    for row in re.findall(r"<tr.*?</tr>", text, re.S):
        c = cells(row)
        if not any(c):
            continue
        # Section header rows are a single cell holding a directory path.
        if len(c) == 1 and c[0].endswith("/"):
            section = "test" if "/test/" in c[0] else "src"
            continue
        # Data rows: file | eCov | eTot | e% | bCov | bTot | b%
        if len(c) >= 7 and c[0].endswith(".lisp"):
            name, ecov, etot, epct, bcov, btot, bpct = c[:7]
            if section == "src":
                rows.append((name, epct, bpct))
                try:
                    src_cov += int(ecov)
                    src_tot += int(etot)
                except ValueError:
                    pass

    overall = (100.0 * src_cov / src_tot) if src_tot else 0.0

    print("## Test coverage (`sb-cover`)\n")
    print(f"**Library sources: {overall:.1f}% of expressions "
          f"({src_cov}/{src_tot}) exercised by the suite.**\n")
    print("| Source file | Expression % | Branch % |")
    print("|---|---:|---:|")
    for name, epct, bpct in rows:
        print(f"| `{name}` | {epct} | {bpct} |")
    print("\n_Network I/O paths (transport/responder sends) are lower by design "
          "— CI has no live multicast. Full HTML report is in the "
          "`coverage-html` artifact._")
    return 0


if __name__ == "__main__":
    sys.exit(main())
