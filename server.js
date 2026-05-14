import express from 'express';

const app  = express();
const PORT = process.env.PORT || 3000;

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const GROQ_API_KEY      = process.env.GROQ_API_KEY;
const APP_SECRET        = process.env.APP_SECRET;

app.use(express.json({ limit: '20mb' }));

// ─── Rate limiter (200 req / heure / IP) ────────────────────────────────────
const rateMap = new Map();
function rateLimit(ip) {
  const now  = Date.now();
  const slot = rateMap.get(ip) ?? { n: 0, reset: now + 3_600_000 };
  if (now > slot.reset) { slot.n = 0; slot.reset = now + 3_600_000; }
  slot.n++;
  rateMap.set(ip, slot);
  return slot.n <= 200;
}
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
app.get('/health', (_, res) => res.json({
  ok: true,
  service: 'REMI Proxy',
  groq:     !!GROQ_API_KEY,
  anthropic: !!ANTHROPIC_API_KEY,
}));

// ─── /api/chat — endpoint unifié ─────────────────────────────────────────────
// provider: "groq" (défaut, gratuit) | "anthropic" (vision, analyse lourde)
// body: { provider?, system, messages: [{role,content}], max_tokens? }
app.post('/api/chat', auth, async (req, res) => {
  const ip = (req.headers['x-forwarded-for'] ?? req.socket.remoteAddress ?? '').split(',')[0].trim();
  if (!rateLimit(ip)) {
    return res.status(429).json({ error: 'Trop de requêtes. Réessaie dans une heure.' });
  }

  const { provider = 'groq', system, messages = [], max_tokens = 1024 } = req.body;

  // ── Groq (LLaMA 3.3 70B — gratuit) ─────────────────────────────────────────
  if (provider === 'groq') {
    if (!GROQ_API_KEY) return res.status(500).json({ error: 'GROQ_API_KEY non configurée.' });
    try {
      const groqMessages = [];
      if (system) groqMessages.push({ role: 'system', content: system });
      groqMessages.push(...messages);

      const upstream = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type':  'application/json',
          'Authorization': `Bearer ${GROQ_API_KEY}`,
        },
        body: JSON.stringify({
          model:      req.body.model ?? 'llama-3.3-70b-versatile',
          max_tokens,
          messages:   groqMessages,
          temperature: 0.7,
        }),
      });

      const data = await upstream.json();
      if (!upstream.ok) {
        console.error('Groq error:', data);
        return res.status(upstream.status).json({ error: data.error?.message ?? 'Erreur Groq.' });
      }
      const text = data.choices?.[0]?.message?.content ?? '';
      return res.json({ text, provider: 'groq' });

    } catch (err) {
      console.error('Groq fetch error:', err);
      return res.status(502).json({ error: 'Erreur proxy vers Groq.' });
    }
  }

  // ── Anthropic (Claude — vision & analyse complexe) ──────────────────────────
  if (provider === 'anthropic') {
    if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'ANTHROPIC_API_KEY non configurée.' });
    try {
      const upstream = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type':      'application/json',
          'x-api-key':          ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model:      req.body.model ?? 'claude-opus-4-7',
          max_tokens,
          system,
          messages,
        }),
      });

      const data = await upstream.json();
      if (!upstream.ok) {
        console.error('Anthropic error:', data);
        return res.status(upstream.status).json({ error: data.error?.message ?? 'Erreur Anthropic.' });
      }
      const text = data.content?.[0]?.text ?? '';
      return res.json({ text, provider: 'anthropic' });

    } catch (err) {
      console.error('Anthropic fetch error:', err);
      return res.status(502).json({ error: 'Erreur proxy vers Anthropic.' });
    }
  }

  return res.status(400).json({ error: `Provider inconnu: ${provider}` });
});

// ─── /api/messages — ancien endpoint Anthropic (backward compat) ─────────────
app.post('/api/messages', auth, async (req, res) => {
  const ip = (req.headers['x-forwarded-for'] ?? req.socket.remoteAddress ?? '').split(',')[0].trim();
  if (!rateLimit(ip)) return res.status(429).json({ error: 'Trop de requêtes.' });
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'ANTHROPIC_API_KEY non configurée.' });
  try {
    const upstream = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':          ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
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

app.listen(PORT, () => console.log(`✅  REMI Proxy démarré — Groq: ${!!GROQ_API_KEY ? '✓' : '✗'}  Anthropic: ${!!ANTHROPIC_API_KEY ? '✓' : '✗'}`));
