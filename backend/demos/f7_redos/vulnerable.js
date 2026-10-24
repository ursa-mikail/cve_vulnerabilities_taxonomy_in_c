// Validates "a string of letter a". The nested quantifier (a+)+ lets the engine split a run of
// a's in exponentially many ways when the match finally fails.
const re = /^(a+)+$/;                     // VULNERABLE (CWE-1333)

re.test('a'.repeat(12) + '!');           // warm-up so the first timing is not dominated by JIT start-up
const times = [];
for (const n of [20, 22, 24, 25, 26]) {
  const input = 'a'.repeat(n) + '!';     // the trailing '!' guarantees the match fails
  const t0 = process.hrtime.bigint();
  re.test(input);
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  times.push(ms);
  console.log(`[demo] ${String(n + 1).padStart(2)}-character input -> ${ms.toFixed(1).padStart(8)} ms`);
}
const last = times[times.length - 1], earlier = times[times.length - 3];
if (last > 20 && last > 2.5 * earlier) {          // two more characters => roughly 4x the work
  console.log('\n[ATTACK SUCCEEDED] each extra character roughly doubles the work. A few dozen bytes from an');
  console.log('                   anonymous client can pin a CPU core and, in single-threaded runtimes, freeze the whole server.');
}
