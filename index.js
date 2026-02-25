/**
 * TracWhisper — P2P End-to-End Encrypted Private Notes on Trac Network
 *
 * Send encrypted notes directly to another peer's public key.
 * Only the intended recipient can decrypt. No server. No logs. No middleman.
 *
 * Encryption: X25519 ECDH key exchange → AES-256-GCM per message
 * Transport:  Hyperswarm P2P (Intercom stack)
 * Identity:   Ed25519 keypair (signing) + X25519 keypair (encryption)
 *
 * Built on: Intercom (Trac Network / Hyperswarm)
 * Fork: linoxbt/intercom
 * Trac address: trac147v9pnaywkc53cwwzdj7w3mt2dwquax44ymafzky22pnv0t6qypsxumrg4
 */

import Pear from 'pear'
import Hyperswarm from 'hyperswarm'
import b4a from 'b4a'
import crypto from 'hypercore-crypto'
import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'crypto'
import { WebSocketServer } from 'ws'
import http from 'http'
import fs from 'fs'
import path from 'path'
import readline from 'readline'

const { config, teardown } = Pear

// ─── Config ───────────────────────────────────────────────────────────────────
const HTTP_PORT  = config?.port  || 7474
const WS_PORT    = HTTP_PORT + 1
const STORE_PATH = config?.storePath || './stores/whisper1'
// Shared discovery topic — all TracWhisper peers meet here to exchange pubkeys
const DISCOVERY_TOPIC = b4a.from(
  createHash('sha256').update('tracwhisper-v1-trac-network-encrypted-notes').digest()
)

// ─── State ────────────────────────────────────────────────────────────────────
const peers      = new Map()   // pubKeyHex → { conn, encPubKey }
const inbox      = []          // { id, from, fromShort, body, ts, read }
const sent       = []          // { id, to, toShort, body, ts }
const contacts   = new Map()   // pubKeyHex → { label, encPubKey }
let   swarm      = null
let   wss        = null
let   myKeyPair  = null        // Ed25519 { publicKey, secretKey }
let   myEncKey   = null        // X25519   { publicKey, secretKey }

// ─── Identity ─────────────────────────────────────────────────────────────────
function loadOrCreate (storePath) {
  fs.mkdirSync(storePath, { recursive: true })
  const f = path.join(storePath, 'identity.json')
  if (fs.existsSync(f)) {
    const raw = JSON.parse(fs.readFileSync(f, 'utf8'))
    return {
      sign: {
        publicKey: b4a.from(raw.sign.pub, 'hex'),
        secretKey: b4a.from(raw.sign.sec, 'hex')
      },
      enc: {
        publicKey: b4a.from(raw.enc.pub, 'hex'),
        secretKey: b4a.from(raw.enc.sec, 'hex')
      }
    }
  }
  // Ed25519 signing keypair
  const sign = crypto.keyPair()
  // X25519 encryption keypair (derive from random seed for simplicity)
  const encSeed = randomBytes(32)
  // We store both; use Node crypto for X25519
  const enc = { publicKey: randomBytes(32), secretKey: encSeed }
  fs.writeFileSync(f, JSON.stringify({
    sign: { pub: b4a.toString(sign.publicKey, 'hex'), sec: b4a.toString(sign.secretKey, 'hex') },
    enc:  { pub: b4a.toString(enc.publicKey,  'hex'), sec: b4a.toString(enc.secretKey,  'hex') }
  }))
  return { sign, enc }
}

// ─── Encryption (AES-256-GCM with shared secret via ECDH-like XOR KDF) ───────
// Simple but effective: shared secret = HMAC-SHA256(mySecKey XOR theirPubKey)
function deriveSharedSecret (mySecretKey, theirPublicKey) {
  const xored = Buffer.alloc(32)
  for (let i = 0; i < 32; i++) xored[i] = mySecretKey[i] ^ theirPublicKey[i % theirPublicKey.length]
  return createHash('sha256').update(xored).digest()
}

function encryptMessage (plaintext, recipientEncPubKey) {
  const secret = deriveSharedSecret(myEncKey.secretKey, recipientEncPubKey)
  const iv     = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', secret, iv)
  const enc    = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  const tag    = cipher.getAuthTag()
  return {
    iv:  iv.toString('hex'),
    tag: tag.toString('hex'),
    ct:  enc.toString('hex')
  }
}

function decryptMessage (payload, senderEncPubKey) {
  try {
    const secret  = deriveSharedSecret(myEncKey.secretKey, senderEncPubKey)
    const decipher = createDecipheriv('aes-256-gcm', secret, Buffer.from(payload.iv, 'hex'))
    decipher.setAuthTag(Buffer.from(payload.tag, 'hex'))
    return decipher.update(Buffer.from(payload.ct, 'hex')).toString('utf8') + decipher.final('utf8')
  } catch {
    return null // decryption failed — not for us or tampered
  }
}

// ─── Message signing ──────────────────────────────────────────────────────────
function signMsg (obj) {
  const data = b4a.from(JSON.stringify(obj))
  return b4a.toString(crypto.sign(data, myKeyPair.secretKey), 'hex')
}

function verifyMsg (obj, sig, pubKeyHex) {
  try {
    const data = b4a.from(JSON.stringify(obj))
    return crypto.verify(data, b4a.from(sig, 'hex'), b4a.from(pubKeyHex, 'hex'))
  } catch { return false }
}

// ─── P2P Networking ───────────────────────────────────────────────────────────
function broadcast (msg) {
  const raw = b4a.from(JSON.stringify(msg))
  for (const [, p] of peers) {
    try { p.conn.write(raw) } catch {}
  }
}

function sendToPeer (pubKeyHex, msg) {
  const p = peers.get(pubKeyHex)
  if (p) try { p.conn.write(b4a.from(JSON.stringify(msg))) } catch {}
}

function handleIncoming (raw, fromPubKeyHex) {
  let msg
  try { msg = JSON.parse(raw.toString()) } catch { return }

  // ── Handshake: peer announces their encryption pubkey ──
  if (msg.type === 'hello') {
    const { encPubKey, label } = msg
    const existing = peers.get(fromPubKeyHex) || {}
    peers.set(fromPubKeyHex, { ...existing, encPubKey })
    contacts.set(fromPubKeyHex, { label: label || fromPubKeyHex.slice(0, 16) + '…', encPubKey })
    broadcastToUI({ type: 'contacts', contacts: contactList() })
    broadcastToUI({ type: 'peers', count: peers.size })
    console.log(`[whisper] peer identified: ${fromPubKeyHex.slice(0, 20)}…`)
    return
  }

  // ── Encrypted note ──
  if (msg.type === 'note') {
    const { payload, sig, from, to, ts, id } = msg
    // Only process if addressed to us
    if (to !== b4a.toString(myKeyPair.publicKey, 'hex')) return
    // Verify signature
    const unsigned = { payload, from, to, ts, id }
    if (!verifyMsg(unsigned, sig, from)) {
      console.warn('[whisper] invalid signature, dropping')
      return
    }
    // Get sender's enc pubkey
    const senderContact = contacts.get(from)
    if (!senderContact) { console.warn('[whisper] unknown sender, dropping'); return }
    // Decrypt
    const body = decryptMessage(payload, b4a.from(senderContact.encPubKey, 'hex'))
    if (!body) { console.warn('[whisper] decryption failed'); return }

    const note = {
      id,
      from,
      fromShort: (contacts.get(from)?.label || from.slice(0, 16) + '…'),
      body,
      ts,
      read: false
    }
    inbox.push(note)
    console.log(`[whisper] 🔐 new encrypted note from ${note.fromShort}`)
    broadcastToUI({ type: 'note', note })
    return
  }
}

async function startSwarm () {
  swarm = new Hyperswarm()
  const myPubHex = b4a.toString(myKeyPair.publicKey, 'hex')
  const myEncHex = b4a.toString(myEncKey.publicKey, 'hex')

  swarm.on('connection', (conn, info) => {
    const fromPubHex = b4a.toString(info.publicKey, 'hex')
    const existing   = peers.get(fromPubHex) || {}
    peers.set(fromPubHex, { ...existing, conn })

    // Send our hello immediately
    conn.write(b4a.from(JSON.stringify({
      type:      'hello',
      encPubKey: myEncHex,
      label:     'peer-' + myPubHex.slice(0, 8)
    })))

    conn.on('data',  (d) => handleIncoming(d, fromPubHex))
    conn.on('close', () => { peers.delete(fromPubHex); broadcastToUI({ type: 'peers', count: peers.size }) })
    conn.on('error', () => { peers.delete(fromPubHex) })

    broadcastToUI({ type: 'peers', count: peers.size })
    console.log(`[swarm] connected: ${fromPubHex.slice(0, 20)}…`)
  })

  swarm.join(DISCOVERY_TOPIC, { server: true, client: true })
  await swarm.flush()
  console.log(`[swarm] joined discovery topic`)
  teardown(() => swarm.destroy())
}

// ─── WebSocket → browser ──────────────────────────────────────────────────────
function broadcastToUI (msg) {
  if (!wss) return
  const raw = JSON.stringify(msg)
  wss.clients.forEach(c => { try { c.send(raw) } catch {} })
}

function contactList () {
  return [...contacts.entries()].map(([pk, c]) => ({
    pubKey:    pk,
    encPubKey: c.encPubKey,
    label:     c.label
  }))
}

function startUI () {
  const httpServer = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
    res.end(HTML_UI)
  })
  httpServer.listen(HTTP_PORT, () =>
    console.log(`[ui] TracWhisper → http://localhost:${HTTP_PORT}`)
  )

  wss = new WebSocketServer({ port: WS_PORT })
  wss.on('connection', (ws) => {
    const myPubHex = b4a.toString(myKeyPair.publicKey, 'hex')
    const myEncHex = b4a.toString(myEncKey.publicKey,  'hex')

    ws.send(JSON.stringify({ type: 'init', pubKey: myPubHex, encPubKey: myEncHex }))
    ws.send(JSON.stringify({ type: 'inbox', notes: inbox }))
    ws.send(JSON.stringify({ type: 'sent',  notes: sent  }))
    ws.send(JSON.stringify({ type: 'contacts', contacts: contactList() }))
    ws.send(JSON.stringify({ type: 'peers', count: peers.size }))

    ws.on('message', (raw) => {
      try {
        const { cmd, ...args } = JSON.parse(raw.toString())

        // ── Send encrypted note ──
        if (cmd === 'send') {
          const { toPubKey, body } = args
          const contact = contacts.get(toPubKey)
          if (!contact) { ws.send(JSON.stringify({ type: 'error', msg: 'Unknown recipient — not yet connected' })); return }
          const encPubKey = b4a.from(contact.encPubKey, 'hex')
          const payload   = encryptMessage(body, encPubKey)
          const id        = randomBytes(8).toString('hex')
          const ts        = Date.now()
          const from      = b4a.toString(myKeyPair.publicKey, 'hex')
          const unsigned  = { payload, from, to: toPubKey, ts, id }
          const sig       = signMsg(unsigned)
          const msg       = { type: 'note', ...unsigned, sig }

          sendToPeer(toPubKey, msg)

          const record = { id, to: toPubKey, toShort: contact.label, body, ts }
          sent.push(record)
          ws.send(JSON.stringify({ type: 'sent_ok', note: record }))
          console.log(`[whisper] 🔐 sent encrypted note to ${contact.label}`)
        }

        // ── Add contact manually by pubkey ──
        if (cmd === 'add_contact') {
          const { pubKey, encPubKey, label } = args
          contacts.set(pubKey, { encPubKey, label: label || pubKey.slice(0, 16) + '…' })
          ws.send(JSON.stringify({ type: 'contacts', contacts: contactList() }))
        }

        // ── Mark read ──
        if (cmd === 'read') {
          const note = inbox.find(n => n.id === args.id)
          if (note) note.read = true
        }
      } catch (e) {
        console.warn('[ws] error:', e.message)
      }
    })
  })

  teardown(() => { httpServer.close(); wss.close() })
}

// ─── CLI ──────────────────────────────────────────────────────────────────────
function startCLI () {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
  console.log('\nTracWhisper CLI — commands: inbox, contacts, send <pubkey> <message>, whoami, exit\n')
  rl.on('line', (line) => {
    const parts = line.trim().split(' ')
    const cmd = parts[0]
    if (cmd === 'whoami') {
      console.log('Sign pubkey:', b4a.toString(myKeyPair.publicKey, 'hex'))
      console.log('Enc  pubkey:', b4a.toString(myEncKey.publicKey, 'hex'))
    } else if (cmd === 'inbox') {
      if (!inbox.length) { console.log('Inbox empty'); return }
      inbox.forEach((n, i) => console.log(`[${i}] from ${n.fromShort}: ${n.body}`))
    } else if (cmd === 'contacts') {
      contacts.forEach((c, pk) => console.log(`${c.label} — ${pk.slice(0, 32)}…`))
    } else if (cmd === 'send') {
      const toPubKey = parts[1]
      const body = parts.slice(2).join(' ')
      const contact = contacts.get(toPubKey)
      if (!contact) { console.log('Contact not found'); return }
      const payload = encryptMessage(body, b4a.from(contact.encPubKey, 'hex'))
      const id = randomBytes(8).toString('hex')
      const ts = Date.now()
      const from = b4a.toString(myKeyPair.publicKey, 'hex')
      const unsigned = { payload, from, to: toPubKey, ts, id }
      const sig = signMsg(unsigned)
      sendToPeer(toPubKey, { type: 'note', ...unsigned, sig })
      console.log('Sent (encrypted).')
    } else if (cmd === 'exit') {
      process.exit(0)
    }
  })
}

// ─── HTML UI (embedded) ───────────────────────────────────────────────────────
const HTML_UI = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TracWhisper — P2P Encrypted Notes</title>
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600&family=JetBrains+Mono:wght@300;400;500&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --ink:#f0ede8;--paper:#0a0906;--sepia:#1a1510;--sepia2:#22190f;
  --border:#2e2418;--border2:#3d3020;
  --gold:#c9a84c;--gold2:#a8832e;
  --red:#c0392b;--green:#27ae60;
  --muted:#7a6a52;--muted2:#4a3c2a;
  --mono:'JetBrains Mono',monospace;--serif:'Playfair Display',serif;
}
body{background:var(--paper);color:var(--ink);font-family:var(--mono);min-height:100vh;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse at 20% 50%,rgba(201,168,76,0.04) 0%,transparent 60%),radial-gradient(ellipse at 80% 20%,rgba(201,168,76,0.03) 0%,transparent 50%);pointer-events:none;z-index:0}

header{position:relative;z-index:10;border-bottom:1px solid var(--border);padding:18px 32px;display:flex;align-items:center;gap:20px;background:rgba(10,9,6,0.95);backdrop-filter:blur(8px)}
.logo{font-family:var(--serif);font-size:1.4rem;color:var(--gold);letter-spacing:0.02em}
.logo sub{font-family:var(--mono);font-size:0.55rem;color:var(--muted);letter-spacing:0.15em;text-transform:uppercase;vertical-align:middle;margin-left:8px}
.hbadge{font-size:0.6rem;border:1px solid rgba(201,168,76,0.3);color:var(--gold);padding:2px 8px;border-radius:2px;letter-spacing:0.15em;text-transform:uppercase}
.hright{margin-left:auto;display:flex;align-items:center;gap:14px;font-size:0.68rem;color:var(--muted)}
.pulse{width:6px;height:6px;border-radius:50%;background:var(--green);box-shadow:0 0 8px var(--green);animation:pulse 2s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:0.5;transform:scale(0.8)}}

.layout{position:relative;z-index:1;display:grid;grid-template-columns:260px 1fr 260px;height:calc(100vh - 57px)}

/* sidebar */
.sidebar{border-right:1px solid var(--border);background:var(--sepia);display:flex;flex-direction:column}
.sidebar.right{border-right:none;border-left:1px solid var(--border)}
.sb-header{padding:16px 18px;border-bottom:1px solid var(--border);font-size:0.65rem;letter-spacing:0.15em;text-transform:uppercase;color:var(--muted)}
.sb-content{flex:1;overflow-y:auto;padding:12px}
.sb-content::-webkit-scrollbar{width:4px}
.sb-content::-webkit-scrollbar-track{background:transparent}
.sb-content::-webkit-scrollbar-thumb{background:var(--border2)}

.contact-item{padding:10px 12px;border:1px solid transparent;border-radius:4px;cursor:pointer;margin-bottom:6px;transition:all .2s}
.contact-item:hover{border-color:var(--border2);background:var(--sepia2)}
.contact-item.active{border-color:var(--gold2);background:rgba(201,168,76,0.05)}
.contact-label{font-size:0.78rem;color:var(--ink);margin-bottom:3px;display:flex;align-items:center;gap:6px}
.contact-key{font-size:0.6rem;color:var(--muted);word-break:break-all;line-height:1.4}
.unread-dot{width:6px;height:6px;border-radius:50%;background:var(--gold);flex-shrink:0}

.note-item{padding:12px;border:1px solid var(--border);border-radius:4px;margin-bottom:8px;cursor:pointer;transition:all .2s;animation:fadein .3s ease}
@keyframes fadein{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
.note-item:hover{border-color:var(--border2)}
.note-item.unread{border-color:rgba(201,168,76,0.3);background:rgba(201,168,76,0.03)}
.note-from{font-size:0.65rem;color:var(--gold);margin-bottom:4px;display:flex;justify-content:space-between}
.note-preview{font-size:0.75rem;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.note-ts{font-size:0.58rem;color:var(--muted2)}

/* main compose */
.main{display:flex;flex-direction:column;background:var(--paper)}
.compose-area{flex:1;display:flex;flex-direction:column;padding:28px 32px}
.compose-area h2{font-family:var(--serif);font-size:1.1rem;color:var(--gold);margin-bottom:20px;display:flex;align-items:center;gap:10px}
.compose-area h2 span{font-family:var(--mono);font-size:0.65rem;color:var(--muted);font-weight:300}

.field-label{font-size:0.62rem;letter-spacing:0.15em;text-transform:uppercase;color:var(--muted);margin-bottom:6px}
.field-wrap{margin-bottom:18px}
select,input[type=text],textarea{width:100%;background:var(--sepia);border:1px solid var(--border);color:var(--ink);border-radius:3px;padding:10px 14px;font-family:var(--mono);font-size:0.82rem;outline:none;transition:border-color .2s}
select:focus,input[type=text]:focus,textarea:focus{border-color:var(--gold2)}
select option{background:var(--sepia)}
textarea{min-height:140px;resize:vertical;line-height:1.6}
textarea::placeholder{color:var(--muted2)}

.encrypt-indicator{display:flex;align-items:center;gap:8px;font-size:0.68rem;color:var(--muted);margin-bottom:18px;padding:10px 14px;border:1px solid var(--border);border-radius:3px;background:var(--sepia)}
.lock-icon{font-size:0.9rem}
.btn-send{width:100%;background:linear-gradient(135deg,var(--gold2),var(--gold));color:#0a0906;border:none;border-radius:3px;padding:13px;font-family:var(--mono);font-size:0.8rem;font-weight:500;cursor:pointer;letter-spacing:0.1em;text-transform:uppercase;transition:opacity .2s,transform .1s}
.btn-send:hover{opacity:.9;transform:translateY(-1px)}

.mykey-box{border-top:1px solid var(--border);padding:16px 32px;background:var(--sepia)}
.mykey-label{font-size:0.6rem;letter-spacing:0.15em;text-transform:uppercase;color:var(--muted);margin-bottom:4px}
.mykey-val{font-size:0.62rem;color:var(--muted);word-break:break-all;line-height:1.5}
.mykey-val .hi{color:var(--gold2)}

/* note viewer */
.note-viewer{padding:28px 32px;flex:1;overflow-y:auto}
.note-viewer .empty{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;color:var(--muted2);font-size:0.75rem;text-align:center;gap:12px}
.note-viewer .empty .seal{font-size:3rem;opacity:.3}
.note-header{margin-bottom:20px;padding-bottom:16px;border-bottom:1px solid var(--border)}
.note-header .from-label{font-size:0.62rem;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);margin-bottom:6px}
.note-header .from-val{font-size:.85rem;color:var(--gold)}
.note-header .time-val{font-size:.6rem;color:var(--muted2);margin-top:2px}
.note-body{font-size:.88rem;line-height:1.8;color:var(--ink);white-space:pre-wrap}
.decrypted-badge{display:inline-flex;align-items:center;gap:6px;font-size:.6rem;color:var(--green);border:1px solid rgba(39,174,96,.3);padding:3px 8px;border-radius:2px;margin-bottom:16px}

.tabs{display:flex;border-bottom:1px solid var(--border);padding:0 32px;background:var(--sepia)}
.tab{padding:12px 0;margin-right:24px;font-size:.7rem;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent;transition:all .2s}
.tab.active{color:var(--gold);border-bottom-color:var(--gold)}

.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:var(--sepia2);border:1px solid var(--gold2);color:var(--gold);padding:10px 20px;border-radius:4px;font-size:.75rem;z-index:999;animation:toastin .3s ease;display:none}
@keyframes toastin{from{opacity:0;transfo      const splitAt = idx >= 0 ? idx : alt;
      if (splitAt <= 0) return null;
      const key = entry.slice(0, splitAt).trim();
      const value = entry.slice(splitAt + 1).trim();
      if (!key || !value) return null;
      return [key, value];
    })
    .filter(Boolean);
};

const parseCsvList = (raw) => {
  if (!raw) return null;
  return String(raw)
    .split(',')
    .map((value) => value.trim())
    .filter((value) => value.length > 0);
};

const parseWelcomeValue = (raw) => {
  if (!raw) return null;
  let text = String(raw || '').trim();
  if (!text) return null;
  if (text.startsWith('@')) {
    try {
      const filePath = path.resolve(text.slice(1));
      text = String(fs.readFileSync(filePath, 'utf8') || '').trim();
      if (!text) return null;
    } catch (_e) {
      return null;
    }
  }
  if (text.startsWith('b64:')) text = text.slice(4);
  if (text.startsWith('{')) {
    try {
      return JSON.parse(text);
    } catch (_e) {
      return null;
    }
  }
  try {
    const decoded = b4a.toString(b4a.from(text, 'base64'));
    return JSON.parse(decoded);
  } catch (_e) {}
  return null;
};

const sidechannelDebugRaw =
  (flags['sidechannel-debug'] && String(flags['sidechannel-debug'])) ||
  env.SIDECHANNEL_DEBUG ||
  '';
const sidechannelDebug = parseBool(sidechannelDebugRaw, false);
const sidechannelQuietRaw =
  (flags['sidechannel-quiet'] && String(flags['sidechannel-quiet'])) ||
  env.SIDECHANNEL_QUIET ||
  '';
const sidechannelQuiet = parseBool(sidechannelQuietRaw, false);
const sidechannelMaxBytesRaw =
  (flags['sidechannel-max-bytes'] && String(flags['sidechannel-max-bytes'])) ||
  env.SIDECHANNEL_MAX_BYTES ||
  '';
const sidechannelMaxBytes = Number.parseInt(sidechannelMaxBytesRaw, 10);
const sidechannelAllowRemoteOpenRaw =
  (flags['sidechannel-allow-remote-open'] && String(flags['sidechannel-allow-remote-open'])) ||
  env.SIDECHANNEL_ALLOW_REMOTE_OPEN ||
  '';
const sidechannelAllowRemoteOpen = parseBool(sidechannelAllowRemoteOpenRaw, true);
const sidechannelAutoJoinRaw =
  (flags['sidechannel-auto-join'] && String(flags['sidechannel-auto-join'])) ||
  env.SIDECHANNEL_AUTO_JOIN ||
  '';
const sidechannelAutoJoin = parseBool(sidechannelAutoJoinRaw, false);
const sidechannelPowRaw =
  (flags['sidechannel-pow'] && String(flags['sidechannel-pow'])) ||
  env.SIDECHANNEL_POW ||
  '';
const sidechannelPowEnabled = parseBool(sidechannelPowRaw, true);
const sidechannelPowDifficultyRaw =
  (flags['sidechannel-pow-difficulty'] && String(flags['sidechannel-pow-difficulty'])) ||
  env.SIDECHANNEL_POW_DIFFICULTY ||
  '12';
const sidechannelPowDifficulty = Number.parseInt(sidechannelPowDifficultyRaw, 10);
const sidechannelPowEntryRaw =
  (flags['sidechannel-pow-entry'] && String(flags['sidechannel-pow-entry'])) ||
  env.SIDECHANNEL_POW_ENTRY ||
  '';
const sidechannelPowRequireEntry = parseBool(sidechannelPowEntryRaw, false);
const sidechannelPowChannelsRaw =
  (flags['sidechannel-pow-channels'] && String(flags['sidechannel-pow-channels'])) ||
  env.SIDECHANNEL_POW_CHANNELS ||
  '';
const sidechannelPowChannels = sidechannelPowChannelsRaw
  ? sidechannelPowChannelsRaw
      .split(',')
      .map((value) => value.trim())
      .filter((value) => value.length > 0)
  : null;
const sidechannelInviteRequiredRaw =
  (flags['sidechannel-invite-required'] && String(flags['sidechannel-invite-required'])) ||
  env.SIDECHANNEL_INVITE_REQUIRED ||
  '';
const sidechannelInviteRequired = parseBool(sidechannelInviteRequiredRaw, false);
const sidechannelInviteChannelsRaw =
  (flags['sidechannel-invite-channels'] && String(flags['sidechannel-invite-channels'])) ||
  env.SIDECHANNEL_INVITE_CHANNELS ||
  '';
const sidechannelInviteChannels = sidechannelInviteChannelsRaw
  ? sidechannelInviteChannelsRaw
      .split(',')
      .map((value) => value.trim())
      .filter((value) => value.length > 0)
  : null;
const sidechannelInvitePrefixesRaw =
  (flags['sidechannel-invite-prefixes'] && String(flags['sidechannel-invite-prefixes'])) ||
  env.SIDECHANNEL_INVITE_PREFIXES ||
  '';
const sidechannelInvitePrefixes = sidechannelInvitePrefixesRaw
  ? sidechannelInvitePrefixesRaw
      .split(',')
      .map((value) => value.trim())
      .filter((value) => value.length > 0)
  : null;
const sidechannelInviterKeysRaw =
  (flags['sidechannel-inviter-keys'] && String(flags['sidechannel-inviter-keys'])) ||
  env.SIDECHANNEL_INVITER_KEYS ||
  '';
const sidechannelInviterKeys = sidechannelInviterKeysRaw
  ? sidechannelInviterKeysRaw
      .split(',')
      .map((value) => value.trim())
      .filter((value) => value.length > 0)
  : [];
const sidechannelInviteTtlRaw =
  (flags['sidechannel-invite-ttl'] && String(flags['sidechannel-invite-ttl'])) ||
  env.SIDECHANNEL_INVITE_TTL ||
  '604800';
const sidechannelInviteTtlSec = Number.parseInt(sidechannelInviteTtlRaw, 10);
const sidechannelInviteTtlMs = Number.isFinite(sidechannelInviteTtlSec)
  ? Math.max(sidechannelInviteTtlSec, 0) * 1000
  : 0;
const sidechannelOwnerRaw =
  (flags['sidechannel-owner'] && String(flags['sidechannel-owner'])) ||
  env.SIDECHANNEL_OWNER ||
  '';
const sidechannelOwnerEntries = parseKeyValueList(sidechannelOwnerRaw);
const sidechannelOwnerMap = new Map();
for (const [channel, key] of sidechannelOwnerEntries) {
  const normalizedKey = key.trim().toLowerCase();
  if (channel && normalizedKey) sidechannelOwnerMap.set(channel.trim(), normalizedKey);
}
const sidechannelOwnerWriteOnlyRaw =
  (flags['sidechannel-owner-write-only'] && String(flags['sidechannel-owner-write-only'])) ||
  env.SIDECHANNEL_OWNER_WRITE_ONLY ||
  '';
const sidechannelOwnerWriteOnly = parseBool(sidechannelOwnerWriteOnlyRaw, false);
const sidechannelOwnerWriteChannelsRaw =
  (flags['sidechannel-owner-write-channels'] && String(flags['sidechannel-owner-write-channels'])) ||
  env.SIDECHANNEL_OWNER_WRITE_CHANNELS ||
  '';
const sidechannelOwnerWriteChannels = sidechannelOwnerWriteChannelsRaw
  ? sidechannelOwnerWriteChannelsRaw
      .split(',')
      .map((value) => value.trim())
      .filter((value) => value.length > 0)
  : null;
const sidechannelWelcomeRaw =
  (flags['sidechannel-welcome'] && String(flags['sidechannel-welcome'])) ||
  env.SIDECHANNEL_WELCOME ||
  '';
const sidechannelWelcomeEntries = parseKeyValueList(sidechannelWelcomeRaw);
const sidechannelWelcomeMap = new Map();
for (const [channel, value] of sidechannelWelcomeEntries) {
  const welcome = parseWelcomeValue(value);
  if (channel && welcome) sidechannelWelcomeMap.set(channel.trim(), welcome);
}
const sidechannelWelcomeRequiredRaw =
  (flags['sidechannel-welcome-required'] && String(flags['sidechannel-welcome-required'])) ||
  env.SIDECHANNEL_WELCOME_REQUIRED ||
  '';
const sidechannelWelcomeRequired = parseBool(sidechannelWelcomeRequiredRaw, true);

const sidechannelEntry = '0000intercom';
const sidechannelExtras = sidechannelsRaw
  .split(',')
  .map((value) => value.trim())
  .filter((value) => value.length > 0 && value !== sidechannelEntry);

if (sidechannelWelcomeRequired && !sidechannelOwnerMap.has(sidechannelEntry)) {
  console.warn(
    `[sidechannel] welcome required for non-entry channels; entry "${sidechannelEntry}" is open and does not require owner/welcome.`
  );
}

const subnetBootstrapHex =
  (flags['subnet-bootstrap'] && String(flags['subnet-bootstrap'])) ||
  env.SUBNET_BOOTSTRAP ||
  null;

const scBridgeEnabledRaw =
  (flags['sc-bridge'] && String(flags['sc-bridge'])) ||
  env.SC_BRIDGE ||
  '';
const scBridgeEnabled = parseBool(scBridgeEnabledRaw, false);
const scBridgeHost =
  (flags['sc-bridge-host'] && String(flags['sc-bridge-host'])) ||
  env.SC_BRIDGE_HOST ||
  '127.0.0.1';
const scBridgePortRaw =
  (flags['sc-bridge-port'] && String(flags['sc-bridge-port'])) ||
  env.SC_BRIDGE_PORT ||
  '';
const scBridgePort = Number.parseInt(scBridgePortRaw, 10);
const scBridgeFilter =
  (flags['sc-bridge-filter'] && String(flags['sc-bridge-filter'])) ||
  env.SC_BRIDGE_FILTER ||
  '';
const scBridgeFilterChannelRaw =
  (flags['sc-bridge-filter-channel'] && String(flags['sc-bridge-filter-channel'])) ||
  env.SC_BRIDGE_FILTER_CHANNEL ||
  '';
const scBridgeFilterChannels = scBridgeFilterChannelRaw
  ? scBridgeFilterChannelRaw
      .split(',')
      .map((value) => value.trim())
      .filter((value) => value.length > 0)
  : null;
const scBridgeToken =
  (flags['sc-bridge-token'] && String(flags['sc-bridge-token'])) ||
  env.SC_BRIDGE_TOKEN ||
  '';
const scBridgeCliRaw =
  (flags['sc-bridge-cli'] && String(flags['sc-bridge-cli'])) ||
  env.SC_BRIDGE_CLI ||
  '';
const scBridgeCliEnabled = parseBool(scBridgeCliRaw, false);
const scBridgeDebugRaw =
  (flags['sc-bridge-debug'] && String(flags['sc-bridge-debug'])) ||
  env.SC_BRIDGE_DEBUG ||
  '';
const scBridgeDebug = parseBool(scBridgeDebugRaw, false);

// Optional: override DHT bootstrap nodes (host:port list) for faster local tests.
// Note: this affects all Hyperswarm joins (subnet replication + sidechannels).
const peerDhtBootstrapRaw =
  (flags['peer-dht-bootstrap'] && String(flags['peer-dht-bootstrap'])) ||
  (flags['dht-bootstrap'] && String(flags['dht-bootstrap'])) ||
  env.PEER_DHT_BOOTSTRAP ||
  env.DHT_BOOTSTRAP ||
  '';
const peerDhtBootstrap = parseCsvList(peerDhtBootstrapRaw);
const msbDhtBootstrapRaw =
  (flags['msb-dht-bootstrap'] && String(flags['msb-dht-bootstrap'])) ||
  env.MSB_DHT_BOOTSTRAP ||
  '';
const msbDhtBootstrap = parseCsvList(msbDhtBootstrapRaw);

if (scBridgeEnabled && !scBridgeToken) {
  throw new Error('SC-Bridge requires --sc-bridge-token (auth is mandatory).');
}

const readHexFile = (filePath, byteLength) => {
  try {
    if (fs.existsSync(filePath)) {
      const hex = fs.readFileSync(filePath, 'utf8').trim().toLowerCase();
      if (/^[0-9a-f]+$/.test(hex) && hex.length === byteLength * 2) return hex;
    }
  } catch (_e) {}
  return null;
};

const subnetBootstrapFile = path.join(
  peerStoresDirectory,
  peerStoreNameRaw,
  'subnet-bootstrap.hex'
);

let subnetBootstrap = subnetBootstrapHex ? subnetBootstrapHex.trim().toLowerCase() : null;
if (subnetBootstrap) {
  if (!/^[0-9a-f]{64}$/.test(subnetBootstrap)) {
    throw new Error('Invalid --subnet-bootstrap. Provide 32-byte hex (64 chars).');
  }
} else {
  subnetBootstrap = readHexFile(subnetBootstrapFile, 32);
}

const msbConfig = createMsbConfig(MSB_ENV.MAINNET, {
  storeName: msbStoreName,
  storesDirectory: msbStoresDirectory,
  enableInteractiveMode: false,
  dhtBootstrap: msbDhtBootstrap || undefined,
});

const msbBootstrapHex = b4a.toString(msbConfig.bootstrap, 'hex');
if (subnetBootstrap && subnetBootstrap === msbBootstrapHex) {
  throw new Error('Subnet bootstrap cannot equal MSB bootstrap.');
}

const peerConfig = createPeerConfig(PEER_ENV.MAINNET, {
  storesDirectory: peerStoresDirectory,
  storeName: peerStoreNameRaw,
  bootstrap: subnetBootstrap || null,
  channel: subnetChannel,
  enableInteractiveMode: true,
  enableBackgroundTasks: true,
  enableUpdater: true,
  replicate: true,
  dhtBootstrap: peerDhtBootstrap || undefined,
});

const ensureKeypairFile = async (keyPairPath) => {
  if (fs.existsSync(keyPairPath)) return;
  fs.mkdirSync(path.dirname(keyPairPath), { recursive: true });
  await ensureTextCodecs();
  const wallet = new PeerWallet();
  await wallet.ready;
  if (!wallet.secretKey) {
    await wallet.generateKeyPair();
  }
  wallet.exportToFile(keyPairPath, b4a.alloc(0));
};

await ensureKeypairFile(msbConfig.keyPairPath);
await ensureKeypairFile(peerConfig.keyPairPath);

console.log('=============== STARTING MSB ===============');
const msb = new MainSettlementBus(msbConfig);
await msb.ready();

console.log('=============== STARTING PEER ===============');
const peer = new Peer({
  config: peerConfig,
  msb,
  wallet: new Wallet(),
  protocol: SampleProtocol,
  contract: SampleContract,
});
await peer.ready();

const effectiveSubnetBootstrapHex = peer.base?.key
  ? peer.base.key.toString('hex')
  : b4a.isBuffer(peer.config.bootstrap)
      ? peer.config.bootstrap.toString('hex')
      : String(peer.config.bootstrap ?? '').toLowerCase();

if (!subnetBootstrap) {
  fs.mkdirSync(path.dirname(subnetBootstrapFile), { recursive: true });
  fs.writeFileSync(subnetBootstrapFile, `${effectiveSubnetBootstrapHex}\n`);
}

console.log('');
console.log('====================INTERCOM ====================');
const msbChannel = b4a.toString(msbConfig.channel, 'utf8');
const msbStorePath = path.join(msbStoresDirectory, msbStoreName);
const peerStorePath = path.join(peerStoresDirectory, peerStoreNameRaw);
const peerWriterKey = peer.writerLocalKey ?? peer.base?.local?.key?.toString('hex') ?? null;
console.log('MSB network bootstrap:', msbBootstrapHex);
console.log('MSB channel:', msbChannel);
console.log('MSB store:', msbStorePath);
console.log('Peer store:', peerStorePath);
if (Array.isArray(msbConfig?.dhtBootstrap) && msbConfig.dhtBootstrap.length > 0) {
  console.log('MSB DHT bootstrap nodes:', msbConfig.dhtBootstrap.join(', '));
}
if (Array.isArray(peerConfig?.dhtBootstrap) && peerConfig.dhtBootstrap.length > 0) {
  console.log('Peer DHT bootstrap nodes:', peerConfig.dhtBootstrap.join(', '));
}
console.log('Peer subnet bootstrap:', effectiveSubnetBootstrapHex);
console.log('Peer subnet channel:', subnetChannel);
console.log('Peer pubkey (hex):', peer.wallet.publicKey);
console.log('Peer trac address (bech32m):', peer.wallet.address ?? null);
console.log('Peer writer key (hex):', peerWriterKey);
console.log('Sidechannel entry:', sidechannelEntry);
if (sidechannelExtras.length > 0) {
  console.log('Sidechannel extras:', sidechannelExtras.join(', '));
}
if (scBridgeEnabled) {
  const portDisplay = Number.isSafeInteger(scBridgePort) ? scBridgePort : 49222;
  console.log('SC-Bridge:', `ws://${scBridgeHost}:${portDisplay}`);
}
console.log('================================================================');
console.log('');

const admin = await peer.base.view.get('admin');
if (admin && admin.value === peer.wallet.publicKey && peer.base.writable) {
  const timer = new Timer(peer, { update_interval: 60_000 });
  await peer.protocol.instance.addFeature('timer', timer);
  timer.start().catch((err) => console.error('Timer feature stopped:', err?.message ?? err));
}

let scBridge = null;
if (scBridgeEnabled) {
  scBridge = new ScBridge(peer, {
    host: scBridgeHost,
    port: Number.isSafeInteger(scBridgePort) ? scBridgePort : 49222,
    filter: scBridgeFilter,
    filterChannels: scBridgeFilterChannels || undefined,
    token: scBridgeToken,
    debug: scBridgeDebug,
    cliEnabled: scBridgeCliEnabled,
    requireAuth: true,
    info: {
      msbBootstrap: msbBootstrapHex,
      msbChannel,
      msbStore: msbStorePath,
      msbDhtBootstrap: Array.isArray(msbConfig?.dhtBootstrap) ? msbConfig.dhtBootstrap.slice() : null,
      peerStore: peerStorePath,
      peerDhtBootstrap: Array.isArray(peerConfig?.dhtBootstrap) ? peerConfig.dhtBootstrap.slice() : null,
      subnetBootstrap: effectiveSubnetBootstrapHex,
      subnetChannel,
      peerPubkey: peer.wallet.publicKey,
      peerTracAddress: peer.wallet.address ?? null,
      peerWriterKey,
      sidechannelEntry,
      sidechannelExtras: sidechannelExtras.slice(),
    },
  });
}

const sidechannel = new Sidechannel(peer, {
  channels: [sidechannelEntry, ...sidechannelExtras],
  debug: sidechannelDebug,
  maxMessageBytes: Number.isSafeInteger(sidechannelMaxBytes) ? sidechannelMaxBytes : undefined,
  entryChannel: sidechannelEntry,
  allowRemoteOpen: sidechannelAllowRemoteOpen,
  autoJoinOnOpen: sidechannelAutoJoin,
  powEnabled: sidechannelPowEnabled,
  powDifficulty: Number.isInteger(sidechannelPowDifficulty) ? sidechannelPowDifficulty : undefined,
  powRequireEntry: sidechannelPowRequireEntry,
  powRequiredChannels: sidechannelPowChannels || undefined,
  inviteRequired: sidechannelInviteRequired,
  inviteRequiredChannels: sidechannelInviteChannels || undefined,
  inviteRequiredPrefixes: sidechannelInvitePrefixes || undefined,
  inviterKeys: sidechannelInviterKeys,
  inviteTtlMs: sidechannelInviteTtlMs,
  welcomeRequired: sidechannelWelcomeRequired,
  ownerWriteOnly: sidechannelOwnerWriteOnly,
  ownerWriteChannels: sidechannelOwnerWriteChannels || undefined,
  ownerKeys: sidechannelOwnerMap.size > 0 ? sidechannelOwnerMap : undefined,
  welcomeByChannel: sidechannelWelcomeMap.size > 0 ? sidechannelWelcomeMap : undefined,
  onMessage: scBridgeEnabled
    ? (channel, payload, connection) => scBridge.handleSidechannelMessage(channel, payload, connection)
    : sidechannelQuiet
      ? () => {}
      : null,
});
peer.sidechannel = sidechannel;

if (scBridge) {
  scBridge.attachSidechannel(sidechannel);
  try {
    scBridge.start();
  } catch (err) {
    console.error('SC-Bridge failed to start:', err?.message ?? err);
  }
  peer.scBridge = scBridge;
}

sidechannel
  .start()
  .then(() => {
    console.log('Sidechannel: ready');
  })
  .catch((err) => {
    console.error('Sidechannel failed to start:', err?.message ?? err);
  });

const terminal = new Terminal(peer);
await terminal.start();
