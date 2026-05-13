import express from 'express';

const app  = express();
const PORT = process.env.PORT || 3000;

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const APP_SECRET        = process.env.APP_SECRET;

app.use(express.json({ limit: '20mb' }));

// ─── Rate limiter (100 req / heure / IP) ────────────────────────────────────
const rateMap = new Map();
function rateLimit(ip) {
  const now  = Date.now();
  const slot = rateMap.get(ip) ?? { n: 0, reset: now + 3_600_000 };
  if (now > slot.reset) { slot.n = 0; slot.reset = now + 3_600_000; }
  slot.n++;
  rateMap.set(ip, slot);
  return slot.n <= 100;
}
// Nettoyage toutes les heures
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of rateMap) { if (now > v.reset) rateMap.delete(k); }
}, 3_600_000);

// ─── Auth middleware ─────────────────────────────────────────────────────────
function auth(req, res, next) {
  if (!APP_SECRET || req.headers['x-app-secret'] !== APP_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ─── Health check ────────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ ok: true, service: 'REMI Proxy' }));

// ─── Proxy Anthropic /v1/messages ───────────────────────────────────────────
app.post('/api/messages', auth, async (req, res) => {
  const ip = (req.headers['x-forwarded-for'] ?? req.socket.remoteAddress ?? '').split(',')[0].trim();
  if (!rateLimit(ip)) {
    return res.status(429).json({ error: 'Trop de requêtes. Réessaie dans une heure.' });
  }
  if (!ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: 'ANTHROPIC_API_KEY non configurée côté serveur.' });
  }
  try {
    const upstream = await fetch('https://api.anthropic.com/v1/messages', {
      method:  'POST',
      headers: {
        'Content-Type':    'application/json',
        'x-api-key':        ANTHROPIC_API_KEY,
        'anthropic-version':'2023-06-01',
      },
      body: JSON.stringify(req.body),
    });
    const data = await upstream.json();
    res.status(upstream.status).json(data);
  } catch (err) {
    console.error('Proxy error:', err);
    res.status(502).json({ error: 'Erreur proxy vers Anthropic.' });
  }
});

app.listen(PORT, () => console.log(`✅  REMI Proxy démarré sur le port ${PORT}`));
