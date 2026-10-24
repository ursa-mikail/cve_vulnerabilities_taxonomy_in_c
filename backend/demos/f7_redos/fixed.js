const re = /^a+$/;                        // FIXED: same language of strings, no nested quantifier
const MAX_LEN = 1000;                     // and a hard cap on untrusted input size

const times = [];
for (const n of [20, 22, 24, 25, 26, 500]) {
  const input = 'a'.repeat(n) + '!';
  if (input.length > MAX_LEN) continue;
  const t0 = process.hrtime.bigint();
  re.test(input);
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  times.push(ms);
  console.log(`[demo] ${String(n + 1).padStart(3)}-character input -> ${ms.toFixed(2).padStart(7)} ms`);
}
if (Math.max(...times) < 50) {
  console.log('\n[BLOCKED] matching time stays flat (linear), however long the hostile input is.');
}
