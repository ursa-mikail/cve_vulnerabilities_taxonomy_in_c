// Applies the facet rules (exported from facet_rules.py) to every CVE row using V8's regex engine,
// which is far faster than Python's `re` on these alternations.
//   node facet_masks.js <csv> <rules.json> <out.masks> <out.stats.json>
// Output: for every CSV row in order, one little-endian uint32 mask per dimension (rules.json key order).
const fs = require('fs');
const { parse } = require('csv-parse');

const [csvPath, rulesPath, outPath, statsPath] = process.argv.slice(2);
const rules = JSON.parse(fs.readFileSync(rulesPath, 'utf8'));
const dims = Object.keys(rules);
const compiled = {};
for (const d of dims) compiled[d] = rules[d].map((v) => ({ key: v.key, bit: v.bit, rules: v.rules.map((r) => ({ field: r.field, kind: r.kind, rx: new RegExp(r.pattern, r.flags) })) }));

const stats = {};
for (const d of dims) { stats[d] = {}; for (const v of rules[d]) stats[d][v.key] = [0, 0]; }

const ND = dims.length;
let masks = new Uint32Array(ND * 450000);
let n = 0;
const parser = fs.createReadStream(csvPath).pipe(parse({ columns: true, relax_quotes: true, relax_column_count: true, skip_empty_lines: true }));
parser.on('data', (row) => {
  if (ND * (n + 1) > masks.length) { const g = new Uint32Array(masks.length * 2); g.set(masks); masks = g; }
  const vp = `${row.vendor} ${row.product} ${row.assigner}`;
  const desc = row.description || '';
  const any = `${vp} ${desc}`;
  const counted = row.family_id !== 'R0';
  dims.forEach((d, di) => {
    let m = 0;
    for (const v of compiled[d]) {
      let hit = false, hitText = false;
      for (const r of v.rules) {
        const src = r.field === 'vp' ? vp : r.field === 'desc' ? desc : any;
        if (r.rx.test(src)) { hit = true; if (r.kind === 'text') hitText = true; }
      }
      if (hit) {
        m |= (1 << v.bit) >>> 0;
        if (counted) { stats[d][v.key][0]++; if (!hitText) stats[d][v.key][1]++; }
      }
    }
    masks[ND * n + di] = m >>> 0;
  });
  n++;
  if (n % 50000 === 0) console.log(`  ${n} rows`);
});
parser.on('end', () => {
  fs.writeFileSync(outPath, Buffer.from(masks.buffer, 0, n * ND * 4));
  fs.writeFileSync(statsPath, JSON.stringify({ rows: n, stats }));
  console.log(`done: ${n} rows`);
});
parser.on('error', (e) => { console.error(e); process.exit(1); });
