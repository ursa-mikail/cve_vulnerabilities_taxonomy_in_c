#!/usr/bin/env python3
"""v3 -> v4 repair of the CVE-to-family mapping.

    python3 tools/repair_mapping.py cve_family_mapping_v3.csv cve_family_mapping_v4.csv repair_changelog_v3_to_v4.csv

Streams the CSV in chunks (it is ~380 MB). Adds two columns, v3_family_id and repair_rule, and writes a
changelog with one line per changed row so every change can be audited or reverted.
"""
import csv
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mapping_rules as R  # noqa: E402

TAX = json.loads((Path(__file__).resolve().parent.parent / "backend" / "taxonomy.json").read_text())
FAM_NAME = {f["id"]: f["name"] for f in TAX["families"]}
U0_NAME = "Unclassified (insufficient public information)"
U0_SUB = "No CWE and no recognisable weakness wording"
KEYWORD_ONLY = ("description keywords", "CNA problem-type text keywords")


def set_row(df, idx, fam, sub, rule, method, conf):
    df.loc[idx, ["family_id", "family_name", "subcategory", "mapping_method", "mapping_confidence", "repair_rule"]] = \
        [fam, FAM_NAME[fam], sub, method, conf, rule]


def ladder(desc):
    for rx, fam, sub in R.LADDER:
        if rx.search(desc):
            return fam, sub
    return None


def repair(df):
    df["v3_family_id"] = df["family_id"]
    df["repair_rule"] = ""
    desc = df["description"]

    # R1: wrong family inherited from an over-general ancestor CWE
    for cwe, (fam, sub, why) in R.CWE_OVERRIDES.items():
        for idx in df.index[(df.primary_cwe == cwe) & (df.family_id != fam)]:
            set_row(df, idx, fam, sub, "R1-cwe-override",
                    f"{cwe} direct mapping (v4 override: {why})", "high")

    # R2: umbrella-CWE refinement kept only if the description names the target weakness
    cand = df.index[(df.repair_rule == "") & df.mapping_method.str.contains("generic class", na=False)
                    & df.primary_cwe.isin(R.GATED)]
    for idx in cand:
        cwe, fam = df.at[idx, "primary_cwe"], df.at[idx, "family_id"]
        home, hsub = R.GENERIC_HOME[cwe]
        if fam != home and not R.EVIDENCE[fam].search(desc.at[idx]):
            set_row(df, idx, home, hsub, "R2-umbrella-refinement-reverted",
                    f"{cwe} (generic class): v3 refinement to {fam} reverted, description names no {fam} weakness [v4]", "medium")

    # R2b: CWE-20 pushed into a memory family with no memory evidence
    c20 = df.index[(df.repair_rule == "") & (df.primary_cwe == "CWE-20") & df.family_id.isin(R.MEMORY_FAMILIES)]
    for idx in c20:
        d = desc.at[idx]
        if not R.MEMORY_KEEP.search(d):
            hit = ladder(d) or R.GENERIC_HOME["CWE-20"]
            set_row(df, idx, hit[0], hit[1], "R2b-cwe20-unsupported-memory-label",
                    "CWE-20 (generic class): v3 memory-family label had no memory evidence; re-read description [v4]", "low")

    # R3: keyword-only 'Memory corruption (unspecified)' with no memory evidence
    kw = df.index[(df.repair_rule == "") & (df.subcategory == "Memory corruption (unspecified)")
                  & df.mapping_method.str.startswith(KEYWORD_ONLY)]
    for idx in kw:
        d = desc.at[idx]
        if R.MEMORY_KEEP.search(d):
            continue
        hit = ladder(d)
        if hit:
            set_row(df, idx, hit[0], hit[1], "R3-unsupported-memory-label",
                    "description names a specific weakness; v3 'memory corruption' label came from an impact phrase [v4]", "low")
        else:
            df.loc[idx, ["family_id", "family_name", "subcategory", "mapping_method", "mapping_confidence", "repair_rule",
                         "best_guess_family", "u0_reason"]] = [
                "U0", U0_NAME, U0_SUB, "none", "none", "R3-unsupported-memory-label", "F5",
                "v4: v3 filed this as memory corruption only because the text says 'execute arbitrary code' "
                "(an impact, not a weakness). Among CVEs that have a specific CWE and the same wording, ~56% are "
                "injection (F5) and ~21% memory (F1-F4), so best_guess_family=F5 is a base-rate prior, "
                "NOT counted in analytics"]

    # R4: 'format string' wording with no CWE
    fs = df.index[(df.repair_rule == "") & (df.primary_cwe == "") & (df.family_id != "F5")
                  & df.mapping_method.str.startswith(KEYWORD_ONLY) & desc.str.contains("format string", case=False, na=False)
                  & ~df.family_id.isin(["U0", "R0"])]
    for idx in fs:
        set_row(df, idx, "F5", "Format string injection", "R4-format-string-wording",
                "description keywords: 'format string' [v4]", "low")

    # R5: surface AI / agent prompt injection as its own subcategory (inside F5)
    pi = df.index[(df.repair_rule == "") & (df.family_id == "F5")
                  & (df.primary_cwe.isin(R.PROMPT_INJECTION_CWES) | desc.str.contains(R.PROMPT_INJECTION))]
    df.loc[pi, "subcategory"] = R.PROMPT_SUBCAT
    df.loc[pi, "repair_rule"] = "R5-prompt-injection-subcategory"
    return df


def main(src, dst, log):
    first = True
    changed = 0
    with open(log, "w", newline="") as lf:
        lw = csv.writer(lf)
        lw.writerow(["cve_id", "rule", "v3_family", "v3_subcategory", "v4_family", "v4_subcategory", "primary_cwe", "description_excerpt"])
        for chunk in pd.read_csv(src, dtype=str, na_filter=False, chunksize=40000):
            before_sub = chunk["subcategory"].copy()
            out = repair(chunk)
            ch = out[out.repair_rule != ""]
            for r in ch.itertuples():
                lw.writerow([r.cve_id, r.repair_rule, r.v3_family_id, before_sub[r.Index], r.family_id,
                             r.subcategory, r.primary_cwe, " ".join(r.description.split())[:200]])
            changed += len(ch)
            out.to_csv(dst, mode="w" if first else "a", header=first, index=False, lineterminator="\n")
            first = False
    print(f"done: {changed} rows changed; wrote {dst} and {log}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:])
