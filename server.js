const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const { MongoClient } = require('mongodb');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'kuntosali-jwt-secret-vaihda-tuotannossa';
const ADMIN_KEY = process.env.ADMIN_KEY || 'salikisuli';
const MONGODB_URI = process.env.MONGODB_URI || '';

let _db = null;

async function getDB() {
  if (_db) return _db;
  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  _db = client.db('kuntosaliohjelma');
  return _db;
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

app.post('/api/register', rateLimit(5, 15 * 60 * 1000), async (req, res) => {
  try {
    const { username, password } = req.body ?? {};
    if (!username?.trim() || !password?.trim())
      return res.status(400).json({ error: 'Täytä kaikki kentät' });
    if (username.trim().length < 3)
      return res.status(400).json({ error: 'Käyttäjänimi liian lyhyt (min 3 merkkiä)' });
    if (password.length < 6)
      return res.status(400).json({ error: 'Salasana liian lyhyt (min 6 merkkiä)' });

    const db = await getDB();
    const name = username.trim();
    const existing = await db.collection('users').findOne({ usernameLower: name.toLowerCase() });
    if (existing) return res.status(400).json({ error: 'Käyttäjänimi on jo käytössä' });

    const id = Date.now();
    const hash = bcrypt.hashSync(password, 10);
    await db.collection('users').insertOne({ id, username: name, usernameLower: name.toLowerCase(), password: hash });

    const token = jwt.sign({ id, username: name }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, username: name });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Palvelinvirhe' });
  }
});

app.post('/api/login', rateLimit(10, 15 * 60 * 1000), async (req, res) => {
  try {
    const { username, password } = req.body ?? {};
    const db = await getDB();
    const user = await db.collection('users').findOne({ usernameLower: username?.trim().toLowerCase() });
    if (!user || !bcrypt.compareSync(password ?? '', user.password))
      return res.status(401).json({ error: 'Väärä käyttäjänimi tai salasana' });

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, username: user.username });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Palvelinvirhe' });
  }
});

app.get('/api/logs/last', requireAuth, async (req, res) => {
  try {
    const { names } = req.query;
    const db = await getDB();

    const nameList = String(names || '').split(',').map(n => n.trim()).filter(Boolean);
    if (!nameList.length) return res.json([]);

    const rows = await db.collection('workout_sets').find({
      user_id: req.user.id,
      exercise_name: { $in: nameList },
    }).sort({ date: -1 }).toArray();

    // Per (exercise_name, set_index): latest result for display + all-time best for PR comparison
    const map = new Map();
    for (const row of rows) {
      if (!row.exercise_name) continue;
      const key = `${row.exercise_name}-${row.set_index}`;
      if (!map.has(key)) {
        // First row (date desc) = most recent
        map.set(key, {
          exercise_name: row.exercise_name,
          set_index: row.set_index,
          date: row.date,
          last_weight: row.weight,
          last_reps: row.reps,
          best_weight: row.weight,
          best_reps: row.reps,
        });
      } else {
        const b = map.get(key);
        if (row.weight != null && (b.best_weight == null || row.weight > b.best_weight)) b.best_weight = row.weight;
        if (row.reps   != null && (b.best_reps   == null || row.reps   > b.best_reps))   b.best_reps   = row.reps;
      }
    }
    res.json([...map.values()]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Palvelinvirhe' });
  }
});

app.post('/api/logs', requireAuth, async (req, res) => {
  try {
    const { date, split, day_index, sets } = req.body ?? {};
    if (!date || !Array.isArray(sets))
      return res.status(400).json({ error: 'Virheellinen pyyntö' });

    const db = await getDB();

    for (const s of sets) {
      const filter = {
        user_id: req.user.id,
        date,
        split: String(split),
        day_index: Number(day_index),
        exercise_index: Number(s.exercise_index),
        set_index: Number(s.set_index),
      };
      const entry = {
        ...filter,
        exercise_name: s.exercise_name || null,
        weight: s.weight != null ? Number(s.weight) : null,
        reps: s.reps != null ? Number(s.reps) : null,
      };
      await db.collection('workout_sets').updateOne(filter, { $set: entry }, { upsert: true });
    }

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Palvelinvirhe' });
  }
});

// ── User programs ──────────────────────────────────────────────────────────────

app.get('/api/programs', requireAuth, async (req, res) => {
  try {
    const db = await getDB();
    const list = await db.collection('user_programs').find({ user_id: req.user.id }).toArray();
    res.json(list);
  } catch (e) {
    res.status(500).json({ error: 'Palvelinvirhe' });
  }
});

app.post('/api/programs', requireAuth, async (req, res) => {
  try {
    const { program, split } = req.body ?? {};
    if (!program || !split) return res.status(400).json({ error: 'Virheellinen pyyntö' });
    const db = await getDB();
    const entry = {
      id: Date.now(),
      user_id: req.user.id,
      program,
      split: Number(split),
      created_at: new Date().toISOString().split('T')[0],
    };
    await db.collection('user_programs').insertOne(entry);
    res.json(entry);
  } catch (e) {
    res.status(500).json({ error: 'Palvelinvirhe' });
  }
});

app.delete('/api/programs/:id', requireAuth, async (req, res) => {
  try {
    const db = await getDB();
    const result = await db.collection('user_programs').deleteOne({
      id: Number(req.params.id),
      user_id: req.user.id,
    });
    if (result.deletedCount === 0) return res.status(404).json({ error: 'Ohjelmaa ei löydy' });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Palvelinvirhe' });
  }
});

// ── Comments ──────────────────────────────────────────────────────────────────

app.get('/api/comments', requireAuth, async (req, res) => {
  try {
    const { split, day_index } = req.query;
    const db = await getDB();
    const comments = await db.collection('exercise_comments').find({
      user_id: req.user.id,
      split: String(split),
      day_index: Number(day_index),
    }).toArray();
    res.json(comments);
  } catch (e) {
    res.status(500).json({ error: 'Palvelinvirhe' });
  }
});

app.post('/api/comments', requireAuth, async (req, res) => {
  try {
    const { split, day_index, exercise_index, comment } = req.body ?? {};
    const db = await getDB();
    const filter = {
      user_id: req.user.id,
      split: String(split),
      day_index: Number(day_index),
      exercise_index: Number(exercise_index),
    };
    if (comment?.trim()) {
      await db.collection('exercise_comments').updateOne(filter, { $set: { ...filter, comment: comment.trim() } }, { upsert: true });
    } else {
      await db.collection('exercise_comments').deleteOne(filter);
    }
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Palvelinvirhe' });
  }
});

// ── Workout sets for a specific date ──────────────────────────────────────────

app.get('/api/logs/date', requireAuth, async (req, res) => {
  try {
    const { date } = req.query;
    if (!date) return res.json([]);
    const db = await getDB();
    const sets = await db.collection('workout_sets').find({
      user_id: req.user.id,
      date: String(date),
    }).sort({ exercise_index: 1, set_index: 1 }).toArray();
    res.json(sets);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Palvelinvirhe' });
  }
});

// ── Workout dates for calendar ─────────────────────────────────────────────────

app.get('/api/logs/dates', requireAuth, async (req, res) => {
  try {
    const db = await getDB();
    const sets = await db.collection('workout_sets').find(
      { user_id: req.user.id },
      { projection: { date: 1, split: 1, day_index: 1 } }
    ).toArray();
    const dateMap = new Map();
    for (const s of sets) {
      if (!s.date) continue;
      if (!dateMap.has(s.date)) dateMap.set(s.date, { date: s.date, split: s.split, day_index: s.day_index });
    }
    res.json([...dateMap.values()].sort((a, b) => a.date.localeCompare(b.date)));
  } catch (e) {
    res.status(500).json({ error: 'Palvelinvirhe' });
  }
});

// ── Admin ──────────────────────────────────────────────────────────────────────

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const db = await getDB();
    const users = await db.collection('users').find().toArray();
    const sets = await db.collection('workout_sets').find().toArray();
    const userPrograms = await db.collection('user_programs').find().toArray();

    const now = new Date();
    const thisMonth = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;

    const usersStats = users.map(u => {
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

    const activeThisMonth = usersStats.filter(u => u.lastActive?.startsWith(thisMonth)).length;

    res.json({
      summary: {
        totalUsers: users.length,
        totalSets: sets.length,
        totalPrograms: userPrograms.length,
        activeThisMonth,
      },
      users: usersStats,
    });
  } catch (e) {
    res.status(500).json({ error: 'Palvelinvirhe' });
  }
});

// ── Start ──────────────────────────────────────────────────────────────────────

async function start() {
  try {
    await getDB();
    console.log('MongoDB yhteys muodostettu');
    app.listen(PORT, () => {
      console.log(`\nKuntosaliohjelma käynnissä: http://localhost:${PORT}\n`);
      console.log(`─── Admin ───────────────────────────────────────────`);
      console.log(`URL:    GET http://localhost:${PORT}/api/admin/stats`);
      console.log(`Header: Authorization: Bearer ${ADMIN_KEY}`);
      console.log(`────────────────────────────────────────────────────\n`);
    });
  } catch (e) {
    console.error('Tietokantayhteys epäonnistui:', e.message);
    process.exit(1);
  }
}

start();
