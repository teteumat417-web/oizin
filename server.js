const express = require('express');
const { ImapFlow } = require('imapflow');
const { simpleParser } = require('mailparser');
const fs = require('fs');
const crypto = require('crypto');

const { GMAIL_USER, GMAIL_APP_PASSWORD, ADMIN_PASSWORD, PORT = 3000 } = process.env;
if (!GMAIL_USER || !GMAIL_APP_PASSWORD || !ADMIN_PASSWORD) {
  console.error('Preencha GMAIL_USER, GMAIL_APP_PASSWORD e ADMIN_PASSWORD no arquivo .env');
  process.exit(1);
}

const DB = 'data.json';
let db = { accounts: [], clients: [] };
try { db = JSON.parse(fs.readFileSync(DB)); } catch {}
const save = () => fs.writeFileSync(DB, JSON.stringify(db, null, 1));
const id = () => crypto.randomBytes(6).toString('hex');

const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(express.static('public'));

// Limite de tentativas erradas: 10 a cada 10 minutos por IP
const fails = {};
const blocked = (ip) => {
  const f = fails[ip] || { n: 0, t: Date.now() };
  if (Date.now() - f.t > 600000) { f.n = 0; f.t = Date.now(); }
  fails[ip] = f;
  return f.n >= 10;
};
const hash = (s) => crypto.createHash('sha256').update(String(s)).digest();
const adminOk = (pw) => crypto.timingSafeEqual(hash(pw), hash(ADMIN_PASSWORD));

// Cliente: consulta o código da conta ligada à chave dele
app.post('/api/code', (req, res) => {
  if (blocked(req.ip)) return res.status(429).json({ error: 'Muitas tentativas. Aguarde alguns minutos.' });
  const client = db.clients.find((c) => c.key === String(req.body.key || '').trim());
  if (!client) { fails[req.ip].n++; return res.status(401).json({ error: 'Chave não encontrada.' }); }
  const acc = db.accounts.find((a) => a.id === client.acc);
  if (!acc) return res.status(404).json({ error: 'Conta não encontrada.' });
  res.json({
    name: client.name,
    account: acc.name,
    code: acc.code || null,
    age: acc.at ? Math.floor((Date.now() - acc.at) / 1000) : null,
  });
});

// Admin
const admin = (req, res, next) => {
  if (blocked(req.ip)) return res.status(429).json({ error: 'Muitas tentativas. Aguarde alguns minutos.' });
  if (!adminOk(req.get('x-admin') || '')) { fails[req.ip].n++; return res.status(401).json({ error: 'Senha incorreta.' }); }
  next();
};
app.get('/api/admin/data', admin, (req, res) => res.json(db));
app.post('/api/admin/account', admin, (req, res) => {
  const name = String(req.body.name || '').trim();
  const sender = String(req.body.sender || '').trim();
  if (!name || !sender) return res.status(400).json({ error: 'Informe o nome e o remetente.' });
  db.accounts.push({ id: id(), name, sender, code: null, at: 0 });
  save(); res.json({ ok: true });
});
app.delete('/api/admin/account/:id', admin, (req, res) => {
  db.accounts = db.accounts.filter((a) => a.id !== req.params.id);
  db.clients = db.clients.filter((c) => c.acc !== req.params.id);
  save(); res.json({ ok: true });
});
app.post('/api/admin/client', admin, (req, res) => {
  const name = String(req.body.name || '').trim();
  if (!name || !db.accounts.some((a) => a.id === req.body.acc)) return res.status(400).json({ error: 'Dados inválidos.' });
  db.clients.push({ name, acc: req.body.acc, key: crypto.randomBytes(9).toString('base64url') });
  save(); res.json({ ok: true });
});
app.delete('/api/admin/client/:key', admin, (req, res) => {
  db.clients = db.clients.filter((c) => c.key !== req.params.key);
  save(); res.json({ ok: true });
});

// Leitura do Gmail: a cada 15s, olha os e-mails dos últimos 15 minutos
let running = false;
async function poll() {
  if (running) return;
  running = true;
  const mail = new ImapFlow({
    host: 'imap.gmail.com', port: 993, secure: true, logger: false,
    auth: { user: GMAIL_USER, pass: GMAIL_APP_PASSWORD },
  });
  try {
    await mail.connect();
    const lock = await mail.getMailboxLock('INBOX');
    try {
      const limit = Date.now() - 15 * 60000;
      for await (const m of mail.fetch({ since: new Date(limit) }, { source: true, internalDate: true })) {
        const at = new Date(m.internalDate).getTime();
        if (at < limit) continue;
        const p = await simpleParser(m.source);
        const from = (p.from?.text || '').toLowerCase();
        const acc = db.accounts.find((a) => from.includes(a.sender.toLowerCase()));
        if (!acc || at <= (acc.at || 0)) continue;
        const text = `${p.subject || ''} ${p.text || ''}`;
        const hit = text.match(/\b(\d{6})\b/) || text.match(/\b(\d{4,8})\b/);
        if (hit) { acc.code = hit[1]; acc.at = at; save(); }
      }
    } finally { lock.release(); }
    await mail.logout();
  } catch (e) {
    console.error('Gmail:', e.message);
  } finally { running = false; }
}
setInterval(poll, 15000);
poll();

app.listen(PORT, () => console.log(`Portal rodando na porta ${PORT}`));
