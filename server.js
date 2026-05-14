import express from 'express';

const app  = express();
const PORT = process.env.PORT || 3000;

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const GROQ_API_KEY      = process.env.GROQ_API_KEY;
const APP_SECRET        = process.env.APP_SECRET;

// ─── Allowed model allowlists ────────────────────────────────────────────────
const GROQ_MODELS = new Set([
  'llama-3.3-70b-versatile',
  'llama-3.1-70b-versatile',
  'llama-3.1-8b-instant',
  'mixtral-8x7b-32768',
]);
const ANTHROPIC_MODELS = new Set([
  'claude-opus-4-7',
  'claude-sonnet-4-5',
  'claude-haiku-3-5',
]);

// ─── Constants ───────────────────────────────────────────────────────────────
const MAX_TOKENS_LIMIT = 4096;

app.use(express.json({ limit: '4mb' }));

// ─── Security headers ────────────────────────────────────────────────────────
app.use((_, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

// ─── Rate limiter (200 req / heure / IP — uses socket address only) ──────────
// NOTE: X-Forwarded-For is intentionally NOT used for rate limiting because it
// can be spoofed by any client. On Render.com the real IP is available on the
// socket once trust-proxy is NOT set.
const rateMap = new Map();
function getRealIP(req) {
  // Use the actual TCP socket remote address; ignore X-Forwarded-For
  return req.socket.remoteAddress ?? 'unknown';
}
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
  const ip = getRealIP(req);
  if (!rateLimit(ip)) {
    return res.status(429).json({ error: 'Trop de requêtes. Réessaie dans une heure.' });
  }

  const { provider = 'groq', system, messages = [], max_tokens: rawMaxTokens = 1024 } = req.body;

  // Clamp max_tokens to prevent cost abuse
  const max_tokens = Math.min(Math.max(1, Number(rawMaxTokens) || 1024), MAX_TOKENS_LIMIT);

  // Validate messages is an array
  if (!Array.isArray(messages)) {
    return res.status(400).json({ error: 'messages doit être un tableau.' });
  }

  // ── Groq (LLaMA 3.3 70B — gratuit) ─────────────────────────────────────────
  if (provider === 'groq') {
    if (!GROQ_API_KEY) return res.status(500).json({ error: 'Service indisponible.' });
    // Validate model against allowlist
    const requestedModel = req.body.model;
    const model = (requestedModel && GROQ_MODELS.has(requestedModel))
      ? requestedModel
      : 'llama-3.3-70b-versatile';
    try {
      const groqMessages = [];
      if (system) groqMessages.push({ role: 'system', content: String(system) });
      groqMessages.push(...messages);

      const upstream = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type':  'application/json',
          'Authorization': `Bearer ${GROQ_API_KEY}`,
        },
        body: JSON.stringify({
          model,
          max_tokens,
          messages:   groqMessages,
          temperature: 0.7,
        }),
      });

      const data = await upstream.json();
      if (!upstream.ok) {
        console.error('Groq error:', upstream.status);
        return res.status(upstream.status).json({ error: data.error?.message ?? 'Erreur Groq.' });
      }
      const text = data.choices?.[0]?.message?.content ?? '';
      return res.json({ text, provider: 'groq' });

    } catch (err) {
      console.error('Groq fetch error');
      return res.status(502).json({ error: 'Erreur proxy vers Groq.' });
    }
  }

  // ── Anthropic (Claude — vision & analyse complexe) ──────────────────────────
  if (provider === 'anthropic') {
    if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'Service indisponible.' });
    // Validate model against allowlist
    const requestedModel = req.body.model;
    const model = (requestedModel && ANTHROPIC_MODELS.has(requestedModel))
      ? requestedModel
      : 'claude-opus-4-7';
    try {
      const upstream = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type':      'application/json',
          'x-api-key':          ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model,
          max_tokens,
          system,
          messages,
        }),
      });

      const data = await upstream.json();
      if (!upstream.ok) {
        console.error('Anthropic error:', upstream.status);
        return res.status(upstream.status).json({ error: data.error?.message ?? 'Erreur Anthropic.' });
      }
      const text = data.content?.[0]?.text ?? '';
      return res.json({ text, provider: 'anthropic' });

    } catch (err) {
      console.error('Anthropic fetch error');
      return res.status(502).json({ error: 'Erreur proxy vers Anthropic.' });
    }
  }

  return res.status(400).json({ error: 'Provider non supporté.' });
});

// ─── /api/plan — génération de plan structuré par l'IA ──────────────────────
// Retourne { plan: { summary, tasks[], milestones[] } }
app.post('/api/plan', auth, async (req, res) => {
  const ip = getRealIP(req);
  if (!rateLimit(ip)) return res.status(429).json({ error: 'Trop de requêtes.' });
  if (!GROQ_API_KEY)  return res.status(500).json({ error: 'Service indisponible.' });

  const { projectName, projectDescription, category, deadline, existingTasks = [] } = req.body;
  const today = new Date().toISOString().split('T')[0];

  const systemPrompt = `Tu es un chef de projet expert. Génère un plan d'action COMPLET en JSON valide avec EXACTEMENT cette structure (rien d'autre) :
{
  "summary": "Présentation du plan en 3-4 phrases, comment atteindre l'objectif",
  "tasks": [
    { "title": "...", "priority": "high|medium|low", "dueDate": "YYYY-MM-DD ou null", "estimatedMinutes": 30, "notes": "..." }
  ],
  "milestones": [
    { "title": "...", "date": "YYYY-MM-DD", "notes": "..." }
  ]
}
Règles :
- 8 à 15 tâches concrètes, actionnables, spécifiques au projet
- 3 à 5 jalons clés représentant des étapes importantes
- Dates réalistes à partir d'aujourd'hui (${today})${deadline ? `, deadline finale : ${deadline}` : ''}
- Priorités cohérentes (les premières tâches souvent "high")
- Réponds UNIQUEMENT avec le JSON, pas de texte autour`;

  const userMsg = `Projet : "${projectName}"
Catégorie : ${category}
Description : ${projectDescription || 'Aucune description fournie'}
Tâches déjà existantes : ${existingTasks.length > 0 ? existingTasks.join(', ') : 'aucune'}

Génère le plan complet.`;

  try {
    const upstream = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${GROQ_API_KEY}` },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages: [{ role: 'system', content: systemPrompt }, { role: 'user', content: userMsg }],
        response_format: { type: 'json_object' },
        max_tokens: 2048,
        temperature: 0.6,
      }),
    });

    const data = await upstream.json();
    if (!upstream.ok) return res.status(upstream.status).json({ error: data.error?.message ?? 'Erreur Groq.' });

    const raw = data.choices?.[0]?.message?.content ?? '{}';
    let plan;
    try { plan = JSON.parse(raw); }
    catch { return res.status(500).json({ error: 'Le modèle n\'a pas retourné un JSON valide.' }); }

    // Validation minimale
    if (!plan.tasks || !Array.isArray(plan.tasks)) plan.tasks = [];
    if (!plan.milestones || !Array.isArray(plan.milestones)) plan.milestones = [];
    if (!plan.summary) plan.summary = 'Plan généré par l\'IA.';

    return res.json({ plan });
  } catch (err) {
    console.error('Plan generation error:', err);
    return res.status(502).json({ error: 'Erreur lors de la génération du plan.' });
  }
});

// ─── /api/messages — ancien endpoint Anthropic (backward compat) ─────────────
app.post('/api/messages', auth, async (req, res) => {
  const ip = getRealIP(req);
  if (!rateLimit(ip)) return res.status(429).json({ error: 'Trop de requêtes.' });
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'Service indisponible.' });

  // Validate and sanitize — do NOT pass req.body verbatim to prevent model override / injection
  const { system, messages, max_tokens: rawMaxTokens = 1024 } = req.body;
  if (!Array.isArray(messages)) {
    return res.status(400).json({ error: 'messages doit être un tableau.' });
  }
  const max_tokens = Math.min(Math.max(1, Number(rawMaxTokens) || 1024), MAX_TOKENS_LIMIT);
  const requestedModel = req.body.model;
  const model = (requestedModel && ANTHROPIC_MODELS.has(requestedModel))
    ? requestedModel
    : 'claude-opus-4-7';

  try {
    const upstream = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':          ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({ model, system, messages, max_tokens }),
    });
    const data = await upstream.json();
    if (!upstream.ok) {
      console.error('Anthropic /messages error:', upstream.status);
      return res.status(upstream.status).json({ error: data.error?.message ?? 'Erreur Anthropic.' });
    }
    res.status(upstream.status).json(data);
  } catch (err) {
    console.error('Proxy error');
    res.status(502).json({ error: 'Erreur proxy vers Anthropic.' });
  }
});

app.listen(PORT, () => console.log(`✅  REMI Proxy démarré — Groq: ${!!GROQ_API_KEY ? '✓' : '✗'}  Anthropic: ${!!ANTHROPIC_API_KEY ? '✓' : '✗'}`));
