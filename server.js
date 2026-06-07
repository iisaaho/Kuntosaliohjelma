const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'kuntosali-jwt-secret-vaihda-tuotannossa';
const ADMIN_KEY = process.env.ADMIN_KEY || 'salikisuli';
const DB_PATH = path.join(__dirname, 'data.json');

function readDB() {
  try {
    return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  } catch {
    return { users: [], workout_sets: [] };
  }
}

function writeDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data));
}

// ── Rate limiting ──────────────────────────────────────────────────────────────

const rateLimits = new Map();

function rateLimit(maxAttempts, windowMs) {
  return (req, res, next) => {
    const key = (req.ip || 'unknown') + req.path;
    const now = Date.now();
    let record = rateLimits.get(key);
    if (!record || now > record.resetAt) {
      record = { count: 0, resetAt: now + windowMs };
    }
    record.count++;
    rateLimits.set(key, record);
    if (record.count > maxAttempts) {
      return res.status(429).json({ error: 'Liian monta yritystä. Odota hetki ja yritä uudelleen.' });
    }
    next();
  };
}

// ── Middleware ──────────────────────────────────────────────────────────────────

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'same-origin');
  next();
});

app.use(express.json());
app.use(express.static(__dirname));

// ── Auth ───────────────────────────────────────────────────────────────────────

function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: 'Ei kirjautunut' });
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Istunto vanhentunut, kirjaudu uudelleen' });
  }
}

function requireAdmin(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ') || header.slice(7) !== ADMIN_KEY)
    return res.status(401).json({ error: 'Pääsy kielletty' });
  next();
}

// ── API ────────────────────────────────────────────────────────────────────────

app.post('/api/register', rateLimit(5, 15 * 60 * 1000), (req, res) => {
  const { username, password } = req.body ?? {};
  if (!username?.trim() || !password?.trim())
    return res.status(400).json({ error: 'Täytä kaikki kentät' });
  if (username.trim().length < 3)
    return res.status(400).json({ error: 'Käyttäjänimi liian lyhyt (min 3 merkkiä)' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Salasana liian lyhyt (min 6 merkkiä)' });

  const db = readDB();
  const name = username.trim();
  if (db.users.find(u => u.username.toLowerCase() === name.toLowerCase()))
    return res.status(400).json({ error: 'Käyttäjänimi on jo käytössä' });

  const id = Date.now();
  const hash = bcrypt.hashSync(password, 10);
  db.users.push({ id, username: name, password: hash });
  writeDB(db);

  const token = jwt.sign({ id, username: name }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, username: name });
});

app.post('/api/login', rateLimit(10, 15 * 60 * 1000), (req, res) => {
  const { username, password } = req.body ?? {};
  const db = readDB();
  const user = db.users.find(u => u.username.toLowerCase() === username?.trim().toLowerCase());
  if (!user || !bcrypt.compareSync(password ?? '', user.password))
    return res.status(401).json({ error: 'Väärä käyttäjänimi tai salasana' });

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, username: user.username });
});

app.get('/api/logs/last', requireAuth, (req, res) => {
  const { split, day_index } = req.query;
  const db = readDB();

  const rows = db.workout_sets.filter(s =>
    s.user_id === req.user.id &&
    String(s.split) === String(split) &&
    s.day_index === Number(day_index)
  ).sort((a, b) => b.date.localeCompare(a.date));

  const latest = new Map();
  for (const row of rows) {
    const key = `${row.exercise_index}-${row.set_index}`;
    if (!latest.has(key)) latest.set(key, row);
  }
  res.json([...latest.values()]);
});

app.post('/api/logs', requireAuth, (req, res) => {
  const { date, split, day_index, sets } = req.body ?? {};
  if (!date || !Array.isArray(sets))
    return res.status(400).json({ error: 'Virheellinen pyyntö' });

  const db = readDB();

  for (const s of sets) {
    const existing = db.workout_sets.findIndex(r =>
      r.user_id === req.user.id &&
      r.date === date &&
      String(r.split) === String(split) &&
      r.day_index === Number(day_index) &&
      r.exercise_index === Number(s.exercise_index) &&
      r.set_index === Number(s.set_index)
    );

    const entry = {
      user_id: req.user.id,
      date,
      split: String(split),
      day_index: Number(day_index),
      exercise_index: Number(s.exercise_index),
      set_index: Number(s.set_index),
      weight: s.weight != null ? Number(s.weight) : null,
      reps: s.reps != null ? Number(s.reps) : null,
    };

    if (existing >= 0) db.workout_sets[existing] = entry;
    else db.workout_sets.push(entry);
  }

  writeDB(db);
  res.json({ ok: true });
});

// ── User programs ──────────────────────────────────────────────────────────────

app.get('/api/programs', requireAuth, (req, res) => {
    const db = readDB();
    const list = (db.user_programs || []).filter(p => p.user_id === req.user.id);
    res.json(list);
});

app.post('/api/programs', requireAuth, (req, res) => {
    const { program, split } = req.body ?? {};
    if (!program || !split) return res.status(400).json({ error: 'Virheellinen pyyntö' });
    const db = readDB();
    if (!db.user_programs) db.user_programs = [];
    const entry = {
        id: Date.now(),
        user_id: req.user.id,
        program,
        split: Number(split),
        created_at: new Date().toISOString().split('T')[0],
    };
    db.user_programs.push(entry);
    writeDB(db);
    res.json(entry);
});

app.delete('/api/programs/:id', requireAuth, (req, res) => {
    const db = readDB();
    if (!db.user_programs) return res.json({ ok: true });
    const idx = db.user_programs.findIndex(
        p => p.id === Number(req.params.id) && p.user_id === req.user.id
    );
    if (idx === -1) return res.status(404).json({ error: 'Ohjelmaa ei löydy' });
    db.user_programs.splice(idx, 1);
    writeDB(db);
    res.json({ ok: true });
});

// ── Admin ──────────────────────────────────────────────────────────────────────

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const db = readDB();
  const sets = db.workout_sets || [];
  const userPrograms = db.user_programs || [];

  const now = new Date();
  const thisMonth = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;

  const users = db.users.map(u => {
    const userSets = sets.filter(s => s.user_id === u.id);
    const userProgs = userPrograms.filter(p => p.user_id === u.id);
    const dates = [...new Set(userSets.map(s => s.date))].filter(Boolean).sort();
    const lastActive = dates.length ? dates[dates.length - 1] : null;
    return {
      username: u.username,
      registeredAt: new Date(u.id).toISOString().split('T')[0],
      programs: userProgs.length,
      workoutDays: dates.length,
      sets: userSets.length,
      lastActive,
    };
  }).sort((a, b) => (b.lastActive || '').localeCompare(a.lastActive || ''));

  const activeThisMonth = users.filter(u => u.lastActive?.startsWith(thisMonth)).length;

  res.json({
    summary: {
      totalUsers: db.users.length,
      totalSets: sets.length,
      totalPrograms: userPrograms.length,
      activeThisMonth,
    },
    users,
  });
});

// ── Start ──────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\nKuntosaliohjelma käynnissä: http://localhost:${PORT}\n`);
  console.log(`─── Admin ───────────────────────────────────────────`);
  console.log(`URL:    GET http://localhost:${PORT}/api/admin/stats`);
  console.log(`Header: Authorization: Bearer ${ADMIN_KEY}`);
  console.log(`────────────────────────────────────────────────────\n`);
});
