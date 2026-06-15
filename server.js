const express = require('express')
const sqlite3 = require('sqlite3').verbose()
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const cors = require('cors')
const { WebSocketServer } = require('ws')
const { v4: uuidv4 } = require('uuid')
const http = require('http')
const https = require('https')
const path = require('path')

const app = express()
const server = http.createServer(app)
const wss = new WebSocketServer({ server })

const JWT_SECRET = 'wave_secret_2025_xK9mP'
const ADMIN_KEY = 'wave_admin_vanit_2025'
const PORT = 5000

// Database setup (sqlite3 - no compilation needed)
const db = new sqlite3.Database(path.join(__dirname, 'wave.db'))

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    is_blocked INTEGER DEFAULT 0,
    block_reason TEXT DEFAULT '',
    created_at INTEGER DEFAULT (strftime('%s','now')),
    last_seen INTEGER DEFAULT 0,
    device_info TEXT DEFAULT ''
  )`)
})

// DB helpers (promise-based)
const dbGet = (sql, params = []) => new Promise((res, rej) => db.get(sql, params, (e, r) => e ? rej(e) : res(r)))
const dbAll = (sql, params = []) => new Promise((res, rej) => db.all(sql, params, (e, r) => e ? rej(e) : res(r)))
const dbRun = (sql, params = []) => new Promise((res, rej) => db.run(sql, params, function (e) { e ? rej(e) : res(this) }))

app.use(cors())
app.use(express.json())
app.use(express.static(path.join(__dirname, 'admin')))

// Online users tracker
const onlineUsers = new Map()

wss.on('connection', (ws) => {
  let userId = null

  ws.on('message', async (data) => {
    try {
      const msg = JSON.parse(data)
      if (msg.type === 'auth') {
        try {
          const decoded = jwt.verify(msg.token, JWT_SECRET)
          userId = decoded.id
          const user = await dbGet('SELECT * FROM users WHERE id=?', [userId])
          if (!user || user.is_blocked) { ws.close(); return }
          onlineUsers.set(userId, { ws, username: user.username, email: user.email, deviceInfo: msg.deviceInfo || '' })
          await dbRun('UPDATE users SET last_seen=?, device_info=? WHERE id=?', [Date.now(), msg.deviceInfo || '', userId])
          ws.send(JSON.stringify({ type: 'auth_ok' }))
          broadcastOnlineList()
        } catch (e) { ws.close() }
      } else if (msg.type === 'ping') {
        if (userId) await dbRun('UPDATE users SET last_seen=? WHERE id=?', [Date.now(), userId])
        ws.send(JSON.stringify({ type: 'pong' }))
      }
    } catch (e) { }
  })

  ws.on('close', () => {
    if (userId) { onlineUsers.delete(userId); broadcastOnlineList() }
  })
})

function broadcastOnlineList() {
  const list = [...onlineUsers.entries()].map(([id, u]) => ({ id, username: u.username, email: u.email }))
  const msg = JSON.stringify({ type: 'online_update', users: list })
  wss.clients.forEach(c => { if (c.readyState === 1) c.send(msg) })
}

function authMW(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '')
  if (!token) return res.status(401).json({ error: 'No token' })
  try { req.user = jwt.verify(token, JWT_SECRET); next() }
  catch (e) { res.status(401).json({ error: 'Invalid token' }) }
}

function adminMW(req, res, next) {
  if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(403).json({ error: 'Forbidden' })
  next()
}

// ── Auth routes ──
app.post('/api/signup', async (req, res) => {
  try {
    const { email, username, password } = req.body
    if (!email || !username || !password) return res.json({ error: 'All fields required' })
    if (password.length < 6) return res.json({ error: 'Password must be at least 6 characters' })
    const exists = await dbGet('SELECT id FROM users WHERE email=?', [email.toLowerCase()])
    if (exists) return res.json({ error: 'Email already registered' })
    const hash = await bcrypt.hash(password, 10)
    const id = uuidv4()
    await dbRun('INSERT INTO users (id,email,username,password) VALUES (?,?,?,?)', [id, email.toLowerCase(), username, hash])
    const token = jwt.sign({ id, email, username }, JWT_SECRET, { expiresIn: '30d' })
    res.json({ success: true, token, user: { id, email, username } })
  } catch (e) { res.json({ error: 'Server error: ' + e.message }) }
})

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body
    if (!email || !password) return res.json({ error: 'Email and password required' })
    const user = await dbGet('SELECT * FROM users WHERE email=?', [email.toLowerCase()])
    if (!user) return res.json({ error: 'Email not found' })
    const match = await bcrypt.compare(password, user.password)
    if (!match) return res.json({ error: 'Wrong password' })
    if (user.is_blocked) return res.json({ error: 'BLOCKED', blockReason: user.block_reason })
    const token = jwt.sign({ id: user.id, email: user.email, username: user.username }, JWT_SECRET, { expiresIn: '30d' })
    res.json({ success: true, token, user: { id: user.id, email: user.email, username: user.username } })
  } catch (e) { res.json({ error: 'Server error: ' + e.message }) }
})

app.get('/api/check', authMW, async (req, res) => {
  const user = await dbGet('SELECT * FROM users WHERE id=?', [req.user.id])
  if (!user) return res.json({ error: 'User not found' })
  if (user.is_blocked) return res.json({ error: 'BLOCKED', blockReason: user.block_reason })
  res.json({ valid: true, user: { id: user.id, email: user.email, username: user.username } })
})

// ── Admin routes ──
app.get('/api/admin/users', adminMW, async (req, res) => {
  const users = await dbAll('SELECT id,email,username,is_blocked,block_reason,created_at,last_seen,device_info FROM users ORDER BY last_seen DESC')
  const now = Date.now()
  res.json(users.map(u => ({
    ...u,
    online: onlineUsers.has(u.id),
    last_seen_ago: u.last_seen ? Math.floor((now - u.last_seen) / 1000) : null
  })))
})

app.post('/api/admin/block', adminMW, async (req, res) => {
  const { userId, reason } = req.body
  await dbRun('UPDATE users SET is_blocked=1, block_reason=? WHERE id=?', [reason || '', userId])
  const conn = onlineUsers.get(userId)
  if (conn) {
    conn.ws.send(JSON.stringify({ type: 'blocked', reason: reason || '' }))
    setTimeout(() => { try { conn.ws.close() } catch (e) { } }, 1000)
    onlineUsers.delete(userId)
  }
  broadcastOnlineList()
  res.json({ success: true })
})

app.post('/api/admin/unblock', adminMW, async (req, res) => {
  await dbRun('UPDATE users SET is_blocked=0, block_reason=\'\' WHERE id=?', [req.body.userId])
  res.json({ success: true })
})

app.post('/api/admin/delete', adminMW, async (req, res) => {
  await dbRun('DELETE FROM users WHERE id=?', [req.body.userId])
  const conn = onlineUsers.get(req.body.userId)
  if (conn) { try { conn.ws.close() } catch (e) { } onlineUsers.delete(req.body.userId) }
  res.json({ success: true })
})

server.listen(PORT, () => {
  console.log(`Wave server running on port ${PORT}`)
})

// --- Keep-alive for Render ---
// Render provides RENDER_EXTERNAL_URL automatically in production
app.get('/api/health', (req, res) => {
  res.status(200).send('ok')
})

const EXTERNAL_URL = process.env.RENDER_EXTERNAL_URL
if (EXTERNAL_URL) {
  setInterval(() => {
    https.get(`${EXTERNAL_URL}/api/health`).on('error', (err) => {
      console.error('Keep-alive ping failed:', err.message)
    })
  }, 10 * 60 * 1000) // Ping every 10 minutes
}
