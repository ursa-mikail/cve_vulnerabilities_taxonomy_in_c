#!/usr/bin/env python3
"""Build the filterable fact table used by the Explore tab.

    python3 tools/build_facets.py cve_family_mapping_v4.csv backend/analytics

Writes   facets.bin.gz   one row per non-rejected CVE, fixed-width little-endian columns
         facets.meta.json column layout, dictionaries (families, subcategories, CWEs, vendors) and
                          the facet definitions with measured coverage

Facet values are inferred (see facet_rules.py); this script also measures how often each dimension
found ANYTHING, so the UI can say plainly how much of the record set a filter can see.
"""
import gzip
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import facet_rules as FR  # noqa: E402

TAX = json.loads((Path(__file__).resolve().parent.parent / "backend" / "taxonomy.json").read_text())
FAMILIES = [f["id"] for f in TAX["families"]] + ["U0"]          # R0 (rejected) is not filterable
FAM_IX = {f: i for i, f in enumerate(FAMILIES)}
SEV = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
CONF = {"low": 1, "medium": 2, "high": 3}
COLS = ["cve_id", "family_id", "subcategory", "primary_cwe", "primary_cwe_name", "mapping_confidence",
        "cvss_severity", "vendor", "product", "assigner", "description"]
BAD_VENDOR = {"", "n/a", "N/A", "unknown", "Unknown"}


def run_masks(csv_path):
    """Pattern matching runs in Node (V8's regex engine); Python orchestrates and packs the table."""
    import subprocess
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="facets-"))
    (tmp / "rules.json").write_text(json.dumps(FR.rules_json()))
    subprocess.run(["node", str(Path(__file__).resolve().parent / "facet_masks.js"), str(csv_path),
                    str(tmp / "rules.json"), str(tmp / "out.masks"), str(tmp / "out.stats.json")], check=True)
    masks = np.fromfile(tmp / "out.masks", dtype="<u2").reshape(-1, 3)
    return masks, json.loads((tmp / "out.stats.json").read_text())["stats"]


def main(csv_path, out_dir):
    out_dir = Path(out_dir)
    masks, stats = run_masks(csv_path)
    df = pd.read_csv(csv_path, usecols=[c for c in COLS if c != "description"], dtype=str, na_filter=False)
    assert len(df) == len(masks), "row count mismatch between CSV and masks"
    keep = (df.family_id != "R0").to_numpy()
    df = df[keep].reset_index(drop=True)
    masks = masks[keep]
    for i, dim in enumerate(FR.DIMENSIONS):
        df["m_" + dim] = masks[:, i]
    n = len(df)

    # ---- dictionaries ----
    sub_keys = sorted({f"{f}|{s}" for f, s in zip(df.family_id, df.subcategory)})
    sub_ix = {k: i for i, k in enumerate(sub_keys)}
    cwe_names = (df[df.primary_cwe != ""].drop_duplicates("primary_cwe")
                 .set_index("primary_cwe").primary_cwe_name.to_dict())
    cwes = [""] + sorted(cwe_names, key=lambda c: int(c.split("-")[1]))
    cwe_ix = {c: i for i, c in enumerate(cwes)}
    v = df.vendor.str.strip()
    top_v = v[~v.isin(BAD_VENDOR)].value_counts().head(500)
    vendors = [""] + list(top_v.index)
    vendor_ix = {x: i for i, x in enumerate(vendors)}

    cols = {
        "fam": df.family_id.map(FAM_IX).astype(np.uint8),
        "sub": np.array([sub_ix[f"{f}|{s}"] for f, s in zip(df.family_id, df.subcategory)], dtype=np.uint8),
        "cwe": df.primary_cwe.map(cwe_ix).fillna(0).astype(np.uint16),
        "year": df.cve_id.str[4:8].astype(np.uint16),
        "num": df.cve_id.str[9:].astype(np.uint32),
        "sev": df.cvss_severity.map(SEV).fillna(0).astype(np.uint8),
        "conf": df.mapping_confidence.map(CONF).fillna(0).astype(np.uint8),
        "os": df.m_os.astype(np.uint16), "lang": df.m_lang.astype(np.uint16), "system": df.m_system.astype(np.uint16),
        "vendor": v.map(vendor_ix).fillna(0).astype(np.uint16),
    }
    # sanity: ids round-trip
    rebuilt = "CVE-" + cols["year"].astype(str) + "-" + pd.Series(cols["num"]).astype(str).str.zfill(4)
    assert (rebuilt.to_numpy() == df.cve_id.to_numpy()).all(), "CVE id does not round-trip through (year, number)"

    layout, blob, off = [], bytearray(), 0
    for name, arr in cols.items():
        arr = np.ascontiguousarray(np.asarray(arr))
        pad = (-off) % 4
        blob += b"\0" * pad
        off += pad
        layout.append({"name": name, "dtype": str(arr.dtype), "offset": off, "length": int(arr.shape[0])})
        blob += arr.astype("<" + arr.dtype.str[1:]).tobytes()
        off += arr.nbytes
    with gzip.open(out_dir / "facets.bin.gz", "wb", compresslevel=9) as f:
        f.write(bytes(blob))

    # ---- measured coverage ----
    facets = {}
    for dim, defs in FR.DIMENSIONS.items():
        m = df["m_" + dim].to_numpy()
        values = []
        for bit, (key, label, doc, _r) in enumerate(defs):
            tot, cur_only = stats[dim][key]
            values.append({"key": key, "label": label, "description": doc, "bit": bit,
                           "count": tot, "curated_only": cur_only})
        facets[dim] = {"label": FR.DIM_LABELS[dim], "values": values,
                       "rows_with_any_value": int((m != 0).sum()),
                       "share_with_any_value": round(100 * float((m != 0).mean()), 1)}

    meta = {
        "rows": n, "layout": layout, "families": FAMILIES,
        "family_names": {f["id"]: f["name"] for f in TAX["families"]} | {"U0": "Unclassified"},
        "subcategories": [{"family": k.split("|")[0], "name": k.split("|", 1)[1]} for k in sub_keys],
        "cwes": [{"id": c, "name": cwe_names.get(c, "")} for c in cwes],
        "vendors": vendors, "facets": facets,
        "method": "Facet values are inferred from vendor/product/assigner and description wording, plus short curated "
                  "product lists. A CVE that names nothing has no value in that dimension (it is never guessed).",
    }
    (out_dir / "facets.meta.json").write_text(json.dumps(meta, ensure_ascii=False, separators=(",", ":")))
    print(f"{n} rows; table {len(blob)/1e6:.1f} MB raw -> {(out_dir/'facets.bin.gz').stat().st_size/1e6:.1f} MB gz")
    for dim, f in facets.items():
        print(f"  {dim:7} any value: {f['share_with_any_value']}%   " +
              ", ".join(f"{v['key']}={v['count']}" for v in f["values"]))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(*sys.argv[1:])
