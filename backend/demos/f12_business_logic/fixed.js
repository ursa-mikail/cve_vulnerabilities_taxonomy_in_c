const CATALOG = { laptop: 1200, 'gift-card-500': 500 };          // FIXED: the server owns prices

function checkout(cart) {
  let total = 0;
  for (const item of cart) {
    if (!(item.sku in CATALOG)) throw new Error('unknown item ' + item.sku);
    if (!Number.isInteger(item.qty) || item.qty < 1 || item.qty > 10) throw new Error('invalid quantity for ' + item.sku);
    total += CATALOG[item.sku] * item.qty;                       // client-sent price is ignored
  }
  if (total <= 0) throw new Error('order total must be positive');
  return total;
}

const honest = [{ sku: 'laptop', price: 1200, qty: 1 }];
const forged = [
  { sku: 'laptop', price: 1, qty: 1 },                           // forged price AND ...
  { sku: 'gift-card-500', price: 500, qty: -3 },                 // ... negative quantity
];
console.log('[demo] honest cart  -> charge', checkout(honest));
try {
  checkout(forged);
} catch (e) {
  console.log('[demo] attacker cart -> rejected:', e.message);
  console.log('\n[BLOCKED] the business invariants (known prices, positive whole quantities) are enforced on the server.');
}
