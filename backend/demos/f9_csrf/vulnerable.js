// A model of the web: a browser that attaches a site's cookie to EVERY request aimed at that site,
// no matter which page caused the request -- exactly how browsers behave by default.
const bank = {
  sessions: { 'sess-alice': 'alice' },
  balances: { alice: 1000, mallory: 0 },
  transfer(req) {
    const user = this.sessions[req.cookie];           // VULNERABLE (CWE-352): the cookie alone is "proof"
    if (!user) return 'denied: not logged in';
    this.balances[user] -= req.amount;
    this.balances[req.to] += req.amount;
    return `ok: ${user} sent ${req.amount} to ${req.to}`;
  },
};

const browser = {
  cookieJar: { 'bank.example': 'sess-alice' },       // Alice is logged in to her bank in another tab
  submitForm(fromPage, toHost, params) {
    return bank.transfer({ ...params, cookie: this.cookieJar[toHost] });   // cookie added automatically
  },
};

console.log('[demo] Alice is logged in to bank.example and now opens a page at evil.example.');
console.log('[demo] that page silently submits a hidden form to bank.example ...');
console.log('      ', browser.submitForm('evil.example', 'bank.example', { to: 'mallory', amount: 900 }));
console.log('[demo] balances:', JSON.stringify(bank.balances));
if (bank.balances.mallory === 900) {
  console.log('\n[ATTACK SUCCEEDED] the bank cannot tell Alice\'s intent from a forged request: both carry her cookie.');
}
