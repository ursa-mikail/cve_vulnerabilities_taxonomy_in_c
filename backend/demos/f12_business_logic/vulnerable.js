// A checkout endpoint that trusts the price and quantity sent by the client.
function checkout(cart) {
  let total = 0;
  for (const item of cart) total += item.price * item.qty;     // VULNERABLE (CWE-840): no rules on the inputs
  return total;
}

const honest = [{ sku: 'laptop', price: 1200, qty: 1 }];
const forged = [
  { sku: 'laptop', price: 1200, qty: 1 },
  { sku: 'gift-card-500', price: 500, qty: -3 },               // a NEGATIVE quantity
];
console.log('[demo] honest cart  -> charge', checkout(honest));
const total = checkout(forged);
console.log('[demo] attacker cart -> charge', total);
if (total < 1200) {
  console.log(`\n[ATTACK SUCCEEDED] the order is ${1200 - total} cheaper than the laptop alone. Nothing crashed, no memory was`);
  console.log('                   corrupted: the code did exactly what it said, but the business rule "you cannot buy a negative number" was never written.');
}
