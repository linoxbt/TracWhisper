# IntercomBoard 📡

> **A decentralized, censorship-resistant P2P bulletin board built on Trac Network / Intercom.**

Think Hacker News — but with no server, no admin, no account, and no way to take it down.

**Trac address:** `trac147v9pnaywkc53cwwzdj7w3mt2dwquax44ymafzky22pnv0t6qypsxumrg4`

---

## What is IntercomBoard?

IntercomBoard turns the Intercom P2P stack into a community bulletin board where:

- **Anyone can post** a title, link, or text — signed with their local keypair
- **Anyone can upvote** posts (one vote per keypair per post, enforced cryptographically)
- **Anyone can comment** on posts
- **Everything is replicated** peer-to-peer via Hyperswarm — no central server
- **State is gossip-propagated** to all peers who join the same topic key
- **Identity is a keypair**, not a username/password

Posts, votes, and comments are all signed messages. Invalid signatures are rejected automatically. Double-votes are deduplicated by `postId:voterPublicKey`. The board state converges across peers via a sync-on-connect + gossip protocol.

---

## Architecture

```
Browser (http://localhost:7373)
        │  WebSocket (ws://localhost:7374)
        ▼
  IntercomBoard process (Pear runtime)
  ┌──────────────────────────────────┐
  │  Local keypair (Ed25519)          │
  │  In-memory post/vote/comment DB   │
  │  Message signing + verification   │
  └────────────┬─────────────────────┘
               │ Hyperswarm
               ▼
     ┌──── P2P Network ────┐
     │  Other board peers  │
     │  (gossip protocol)  │
     └─────────────────────┘
```

**Message types:**

| Type | Payload | Dedup strategy |
|------|---------|----------------|
| `post` | id, title, url, body | by `post.id` |
| `vote` | postId | by `postId:voterKey` |
| `comment` | id, postId, text | by `comment.id` |

All messages include: `{ type, data, author (pubkey hex), ts, sig }`. Signature covers `{type, data, author, ts}`.

---

## How to Run

### Prerequisites

```bash
npm install -g pear
pear --version
```

### Install dependencies

```bash
git clone https://github.com/linoxbt/intercom
cd intercom
npm install
```

### Run IntercomBoard

```bash
pear run . --store-path ./stores/board1
```

Then open **http://localhost:7373** in your browser.

To run a second peer (on another machine or terminal):

```bash
pear run . --store-path ./stores/board2 --port 7375
```

Both peers will automatically discover each other via Hyperswarm DHT and sync their board state.

---

## Features

- 🔐 **Cryptographic identity** — Ed25519 keypair generated on first run, persisted locally
- ✅ **Signed messages** — every post, vote, and comment is signed and verified
- 🚫 **No double-voting** — enforced by `postId:voterKey` deduplication across peers
- 🌐 **Browser UI** — clean dark-mode web interface at `http://localhost:7373`
- 🔄 **Sync on connect** — new peers receive current board state when joining
- 📡 **Gossip propagation** — messages forwarded to all connected peers
- 💬 **Comments** — threaded comments per post
- 🔥 **Sort by votes or newest** — toggle in the UI
- 🖥️ **CLI mode** — terminal commands: `post`, `vote`, `list`, `peers`

---

## Screenshots

```
┌─────────────────────────────────────────────────────────────────┐
│ 📡 IntercomBoard  [P2P]   Decentralized…             3 peers    │
├─────────────────────────────────────────────────────────────────┤
│ + Submit Post                                                   │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ Title: Trac Network launches Intercom agent protocol        │ │
│ │ URL:   https://github.com/Trac-Systems/intercom             │ │
│ │ Body:  P2P messaging for AI agents                          │ │
│ │                                           [Broadcast →]     │ │
│ └─────────────────────────────────────────────────────────────┘ │
│                                                                  │
│ Sort: [🔥 Top]  [✨ New]                                         │
│                                                                  │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ 3b9f2a1c8e7d…  · 2/25/2026, 10:42:00 AM                    │ │
│ │ Trac Network launches Intercom agent protocol                │ │
│ │ P2P messaging for AI agents                                  │ │
│ │ [▲ Upvote]  12   [💬 3]                                     │ │
│ └──────────────────────────────────────────────────────────────┘ │
│                                                                  │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ a91d4f3b2c6e…  · 2/25/2026, 10:30:00 AM                    │ │
│ │ DeAI: Why decentralized AI needs decentralized comms        │ │
│ │ [▲ Upvote]  7    [💬 1]                                     │ │
│ └──────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## Competition Entry

This is a fork of [Trac-Systems/intercom](https://github.com/Trac-Systems/intercom) for the **Intercom Vibe Competition**.

- **Trac address:** `trac147v9pnaywkc53cwwzdj7w3mt2dwquax44ymafzky22pnv0t6qypsxumrg4`
- **App:** IntercomBoard — Decentralized P2P bulletin board
- **Fork:** https://github.com/linoxbt/intercom

---

## Original Intercom README

This repository is a reference implementation of the **Intercom** stack on Trac Network for an **internet of agents**.

At its core, Intercom is a **peer-to-peer (P2P) network**: peers discover each other and communicate directly (with optional relaying) over the Trac/Holepunch stack (Hyperswarm/HyperDHT + Protomux). There is no central server required for sidechannel messaging.

Features:
- **Sidechannels**: fast, ephemeral P2P messaging
- **SC-Bridge**: authenticated local WebSocket control surface for agents/tools
- **Contract + protocol**: deterministic replicated state and optional chat
- **MSB client**: optional value-settled transactions via the validator network

For full agent-oriented instructions, see `SKILL.md`.
