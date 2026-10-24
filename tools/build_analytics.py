#!/usr/bin/env python3
"""Rebuild backend/analytics/analytics.json from a family-mapping CSV.

    python3 tools/build_analytics.py cve_family_mapping_v4.csv backend/analytics/analytics.json

Everything in the output is a pure function of the CSV (plus backend/taxonomy.json for names),
so the dashboard can always be regenerated and audited. The only judgement call is the example
CVEs shown per family: they are picked deterministically (see pick_examples).
"""
import hashlib
import json
import sys
from pathlib import Path

import pandas as pd

HERE = Path(__file__).resolve().parent
TAXONOMY = json.loads((HERE.parent / "backend" / "taxonomy.json").read_text())
FAM_NAMES = {f["id"]: f["name"] for f in TAXONOMY["families"]}
FAM_NAMES.update({b["id"]: b["name"] for b in TAXONOMY["bookkeeping"]})
ORDER = [f["id"] for f in TAXONOMY["families"]] + [b["id"] for b in TAXONOMY["bookkeeping"]]
SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

COLS = ["cve_id", "state", "family_id", "subcategory", "primary_cwe", "primary_cwe_name",
        "mapping_method", "mapping_confidence", "cvss_severity", "vendor", "product",
        "assigner", "description", "nvd_url"]


def basis(method):
    """Collapse the free-text mapping_method into a small, honest set of evidence classes."""
    m = str(method)
    if m == "none":
        return "No evidence"
    if m.startswith("CVE state"):
        return "Rejected / withdrawn"
    if "direct mapping" in m or "v4 override" in m:
        return "Specific CWE (direct)"
    if "generic class" in m or "refinement reverted" in m:
        return "Generic CWE + description keywords"
    if "hierarchy" in m:
        return "CWE hierarchy (inherited)"
    if "impact phrase" in m or "re-read description" in m:
        return "Description / advisory keywords"
    if "keyword" in m and "Linux" not in m:
        return "Description / advisory keywords"
    if "Linux" in m:
        return "Linux commit-title heuristic"
    if "classifier" in m:
        return "Text classifier (ML)"
    return "Other"


def pick_examples(sub, n=6):
    """Deterministic: prefer high-confidence rows that carry a CWE, order by a stable hash of the id."""
    s = sub.copy()
    s["_rank"] = (s.mapping_confidence != "high").astype(int) + s.primary_cwe.isna().astype(int)
    s["_h"] = s.cve_id.map(lambda x: hashlib.sha1(x.encode()).hexdigest())
    s = s.sort_values(["_rank", "_h"]).head(n)
    out = []
    for r in s.itertuples():
        d = " ".join(str(r.description).split())
        out.append({
            "id": r.cve_id,
            "title": d if len(d) <= 140 else d[:137] + "...",
            "cwe": "" if pd.isna(r.primary_cwe) else r.primary_cwe,
            "severity": None if pd.isna(r.cvss_severity) else r.cvss_severity,
            "url": r.nvd_url,
        })
    return out


def topn(series, n, drop=("n/a", "N/A", "unknown", "")):
    vc = series.dropna().astype(str).str.strip()
    vc = vc[~vc.isin(drop)].value_counts()
    vc = vc.reset_index().set_axis(["name", "count"], axis=1).sort_values(["count", "name"], ascending=[False, True])
    return [{"name": r.name, "count": int(r.count)} for r in vc.head(n).itertuples()]


def main(csv_path, out_path):
    df = pd.read_csv(csv_path, usecols=COLS, low_memory=False)
    df["year"] = df.cve_id.str[4:8]
    years = [str(y) for y in range(int(df.year.min()), int(df.year.max()) + 1)]
    cwe_names = (df.dropna(subset=["primary_cwe", "primary_cwe_name"])
                   .drop_duplicates("primary_cwe").set_index("primary_cwe").primary_cwe_name.to_dict())

    families = []
    for fid in ORDER:
        sub = df[df.family_id == fid]
        by_year = sub.year.value_counts()
        cw = sub.primary_cwe.dropna().value_counts().head(8)
        sc = sub.subcategory.dropna().value_counts().head(6)
        sev = sub.cvss_severity.value_counts()
        hc = None if fid in ("U0", "R0") or len(sub) == 0 else round(100 * (sub.mapping_confidence == "high").mean(), 1)
        families.append({
            "id": fid, "name": FAM_NAMES[fid], "total": int(len(sub)),
            "by_year": [{"year": y, "count": int(by_year.get(y, 0))} for y in years],
            "top_cwes": [{"cwe": k, "name": cwe_names.get(k, ""), "count": int(v)} for k, v in cw.items()],
            "top_subcategories": [{"name": k, "count": int(v)} for k, v in sc.items()],
            "severity": {s: int(sev.get(s, 0)) for s in SEVS},
            "high_confidence_pct": hc,
            "examples": pick_examples(sub),
        })

    # ---- coverage: every subcategory of every family, with evidence quality ----
    core = df[~df.family_id.isin(["U0", "R0"])].copy()
    core["basis"] = core.mapping_method.map(basis)
    coverage = []
    for fid in [f["id"] for f in TAXONOMY["families"]]:
        sub = core[core.family_id == fid]
        rows = []
        for name, g in sub.groupby("subcategory"):
            top = g.primary_cwe.dropna().value_counts().head(3)
            rows.append({"name": name, "count": int(len(g)),
                         "top_cwes": [{"cwe": k, "count": int(v)} for k, v in top.items()],
                         "high_confidence_pct": round(100 * (g.mapping_confidence == "high").mean(), 1)})
        rows.sort(key=lambda r: -r["count"])
        coverage.append({"family": fid, "total": int(len(sub)), "subcategories": rows,
                         "distinct_cwes": int(sub.primary_cwe.nunique())})

    basis_tbl = (core.assign(conf=core.mapping_confidence.fillna("none"))
                 .groupby(["basis", "conf"]).size().unstack(fill_value=0))
    mapping_basis = [{"basis": b, "total": int(r.sum()),
                      **{c: int(r.get(c, 0)) for c in ["high", "medium", "low"]}}
                     for b, r in basis_tbl.iterrows()]
    mapping_basis.sort(key=lambda r: -r["total"])

    out = {
        "generated_from": "CVE Program full record set (CVEProject/cvelistV5) + NVD CWE/CVSS enrichment",
        "mapping_version": Path(csv_path).stem.split("_")[-1],
        "total_cves": int(len(df)),
        "published_cves": int((df.state == "PUBLISHED").sum()),
        "rejected_cves": int((df.family_id == "R0").sum()),
        "unclassified_cves": int((df.family_id == "U0").sum()),
        "year_range": [years[0], years[-1]],
        "families": families,
        "timeline_total": [{"year": y, "count": int((df.year == y).sum())} for y in years],
        "severity_totals": {s: int((df.cvss_severity == s).sum()) for s in SEVS},
        "top_vendors": topn(df.vendor, 12),
        "top_products": topn(df["product"], 12),
        "top_assigners": topn(df.assigner, 10),
        "coverage": coverage,
        "mapping_basis": mapping_basis,
    }
    Path(out_path).write_text(json.dumps(out, ensure_ascii=False, separators=(",", ":")))
    print(f"wrote {out_path}: {out['total_cves']} CVEs, {len(families)} buckets, "
          f"{sum(len(c['subcategories']) for c in coverage)} subcategories")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
