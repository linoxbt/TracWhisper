# TracWhisper 🔐

> **P2P end-to-end encrypted private notes on Trac Network — built on Intercom.**

Send encrypted messages directly to any peer's public key. Only the intended recipient can decrypt. No server. No logs. No middleman. Ever.

**Trac address:** `trac147v9pnaywkc53cwwzdj7w3mt2dwquax44ymafzky22pnv0t6qypsxumrg4`

**Fork of:** [Trac-Systems/intercom](https://github.com/Trac-Systems/intercom)

---

## Screenshot

<img width="1366" height="688" alt="Screenshot (152)" src="https://github.com/user-attachments/assets/2363a88b-30e9-4028-9b48-66b5c382eb2b" />

![TracWhisper UI — P2P Encrypted Notes]

*Three-panel UI: contacts (left), compose encrypted note (center), inbox + note viewer (right). Terminal shows live peer connections via Hyperswarm.*

---

## What is TracWhisper?

TracWhisper is a private, encrypted messaging app built on the Intercom P2P stack. Unlike chat apps that store your messages on a server, TracWhisper delivers notes directly peer-to-peer — encrypted before they leave your device and decrypted only by the recipient.

**Core properties:**
- 🔐 **End-to-end encrypted** — AES-256-GCM encryption, keyed via ECDH-derived shared secret
- ✍️ **Signed** — every note is signed with Ed25519, proving authorship
- 📡 **Serverless** — no relay, no storage, pure Hyperswarm P2P delivery
- 👤 **Keypair identity** — no accounts, no usernames, just a local keypair
- 🌐 **Browser UI** — clean dark interface at `http://localhost:7474`
- 🖥️ **CLI mode** — full terminal access for agents

---

## How Encryption Works

```
Sender                              Recipient
──────                              ─────────
1. Generate shared secret:          1. Generate shared secret:
   HMAC-SHA256(mySecKey XOR            HMAC-SHA256(mySecKey XOR
   recipientEncPubKey)                 senderEncPubKey)
                                       [same result — symmetric]
2. Encrypt with AES-256-GCM
   (random 12-byte IV per note)     2. Decrypt with AES-256-GCM
                                       (verify GCM auth tag)
3. Sign { payload, from, to,        3. Verify Ed25519 signature
   ts, id } with Ed25519

4. Send over Hyperswarm P2P ──────► 4. Receive, verify, decrypt, read
```

The server (there isn't one) never sees plaintext. Peers who aren't the intended recipient receive nothing — notes are addressed and only delivered to the target peer.

---

## Identity Model

Each peer has two keypairs:

| Keypair | Algorithm | Purpose |
|---------|-----------|---------|
| Sign keypair | Ed25519 | Proving message authorship |
| Enc keypair  | Random 32-byte key | Deriving shared secrets for AES encryption |

Both are generated once on first run and stored in `stores/<name>/identity.json`.

To receive notes from someone, they need your **sign public key** (to address notes to you) and your **enc public key** (to encrypt for you). The UI displays both — just share them.

---

## Architecture

```
Browser (http://localhost:7474)
        │  WebSocket (ws://localhost:7475)
        ▼
  TracWhisper process (Pear runtime)
  ┌────────────────────────────────────────┐
  │  Ed25519 keypair  (sign/verify)         │
  │  Enc keypair      (ECDH shared secret)  │
  │  AES-256-GCM      (encrypt/decrypt)     │
  │  In-memory inbox + sent store           │
  └────────────────┬───────────────────────┘
                   │ Hyperswarm
                   ▼
        ┌─── P2P Discovery ───┐
        │  topic: sha256(     │
        │  "tracwhisper-v1…") │
        │  Hello handshake    │
        │  (exchange enc keys)│
        └─────────────────────┘
```

Discovery flow:
1. Both peers join the same Hyperswarm topic
2. On connect, each sends a `hello` message with their enc public key
3. Peers store each other's enc keys in contacts
4. Notes are encrypted + signed, sent directly over the P2P connection
5. Recipient verifies signature, decrypts, reads

---

## How to Run

### Prerequisites
```bash
npm install -g pear
pear --version
```

### Install & run
```bash
git clone https://github.com/linoxbt/intercom
cd intercom
npm install
pear run . --store-path ./stores/peer1
```

Open **http://localhost:7474** in your browser.

### Run a second peer (to test)
```bash
pear run . --store-path ./stores/peer2 --port 7476
```

Open **http://localhost:7476** — the two peers will auto-discover each other, exchange enc keys, and you can send encrypted notes between them.

---

## WebSocket API (for agents)

Connect to `ws://localhost:7475`. On connect, receive:

```json
{ "type": "init", "pubKey": "<ed25519 hex>", "encPubKey": "<enc hex>" }
{ "type": "contacts", "contacts": [...] }
{ "type": "inbox", "notes": [...] }
{ "type": "peers", "count": 2 }
```

### Send a note
```json
{ "cmd": "send", "toPubKey": "<recipient sign pubkey>", "body": "Hello!" }
```

### Add a contact manually
```json
{ "cmd": "add_contact", "pubKey": "<sign key>", "encPubKey": "<enc key>", "label": "Alice" }
```

### Events from server
```json
{ "type": "note", "note": { "id", "from", "fromShort", "body", "ts", "read" } }
{ "type": "sent_ok", "note": { "id", "to", "toShort", "body", "ts" } }
{ "type": "contacts", "contacts": [...] }
{ "type": "peers", "count": 3 }
```

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `whoami` | Print your sign + enc public keys |
| `inbox` | List received notes |
| `contacts` | List known contacts |
| `send <pubkey> <message>` | Send encrypted note |
| `exit` | Quit |

---

## File Structure

```
intercom/
├── app.js          ← TracWhisper main application
├── SKILL.md        ← Agent instructions
├── README.md       ← This file
├── package.json    ← Dependencies
└── stores/
    └── peer1/
        └── identity.json   ← Your keypairs (auto-generated, never share secretKey)
```

---

## Competition Entry

- **App:** TracWhisper — P2P End-to-End Encrypted Notes
- **Fork:** https://github.com/linoxbt/intercom
- **Trac address:** `trac147v9pnaywkc53cwwzdj7w3mt2dwquax44ymafzky22pnv0t6qypsxumrg4`
- **Base:** Fork of [Trac-Systems/intercom](https://github.com/Trac-Systems/intercom)
