const bank = {
  sessions: { 'sess-alice': { user: 'alice', csrfToken: 'tok-9f31c7' } },   // random per session
  balances: { alice: 1000, mallory: 0, bob: 0 },
  transfer(req) {
    const s = this.sessions[req.cookie];
    if (!s) return 'denied: not logged in';
    if (req.csrfToken !== s.csrfToken) return 'denied: missing or wrong CSRF token';   // FIXED layer 1
    this.balances[s.user] -= req.amount;
    this.balances[req.to] += req.amount;
    return `ok: ${s.user} sent ${req.amount} to ${req.to}`;
  },
};

const browser = {
  cookieJar: { 'bank.example': 'sess-alice' },
  sameSiteLax: true,                                  // FIXED layer 2: cookie is not sent on cross-site POSTs
  submitForm(fromPage, toHost, params) {
    const crossSite = fromPage !== toHost;
    const cookie = this.sameSiteLax && crossSite ? undefined : this.cookieJar[toHost];
    return bank.transfer({ ...params, cookie });
  },
};

console.log('[demo] the same hidden form from evil.example (cannot read the bank\'s token, may be sent without cookie):');
console.log('      ', browser.submitForm('evil.example', 'bank.example', { to: 'mallory', amount: 900 }));
browser.sameSiteLax = false;                           // even on an old browser that ignores SameSite...
console.log('[demo] ...and on a browser that ignores SameSite:');
console.log('      ', browser.submitForm('evil.example', 'bank.example', { to: 'mallory', amount: 900 }));
console.log('[demo] Alice\'s own page, which knows the token:');
console.log('      ', browser.submitForm('bank.example', 'bank.example', { to: 'bob', amount: 10, csrfToken: 'tok-9f31c7' }));
if (bank.balances.mallory === 0) {
  console.log('\n[BLOCKED] forged requests fail twice over: no cookie on cross-site requests, and no valid token.');
}
