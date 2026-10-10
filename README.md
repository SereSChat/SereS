# 💬 SereS

[![Beta Status](https://img.shields.io/badge/Status-Web%20Beta-orange.svg)](https://status.seres-chat.com)
[![Discord](https://img.shields.io/badge/Discord-Join%20Community-5865F2?logo=discord&logoColor=white)](https://discord.gg/vx3vKcp2Kq)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**SereS** is a next-generation web messaging platform designed to bridge the gap between WhatsApp and Discord—faster, cleaner, and built for the modern web.

---

## 🌐 Beta is Live now!

The **SereS Beta** is currently live and directly accessible on our official website. Try out the platform, test the new features, and experience the future of chat right in your browser!

👉 **[Access the SereS Web Beta](https://seres-chat.com)**

---

## ✨ Features

- **Modern & Sleek UI:** A clean, fast, and clutter-free interface designed for the modern web.
- **Best of Both Worlds:** Combines the simple direct messaging of WhatsApp with the rich community structure of Discord.
- **Real-time Engine:** Ultra-fast messaging, rich media sharing, and instant updates.
- **Dynamic Spaces:** Effortlessly jump between private 1-on-1 chats and group chats.
- **End-to-End Encrypted:** Every message is encrypted in your browser. The server only ever sees ciphertext.

---

## 👥 Join the Community

Help us refine SereS during the Beta phase! Share your feedback, report bugs, or chat with the team on our official Discord server.

👉 **[Join the SereS Discord Server](https://discord.gg/vx3vKcp2Kq)**

---

## 🚀 Local Development

If you want to contribute or test the project locally:

```bash
## Windows:

# 1. Clone the repository
git clone https://github.com/SereSChat/SereS.git
cd SereS

# 2. python venv
python -m venv .venv
./\.venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start development server
python src/backend/app.py


## Linux:

# 1. Clone the repository
git clone https://github.com/SereSChat/SereS.git
cd SereS

# 2. python venv
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start development server
python src/backend/app.py
```

The frontend is written in TypeScript (`src/frontend/`). It is compiled to
`src/public/` and the compiled `.js` files are committed;
after changing a `.ts` file run `tsc -p .` in the repository root.

Backend tests: `pip install pytest && python -m pytest tests`

Optional environment variables: `PORT`, `HOST`, `SERES_DEBUG=1` (never in production),
`SERES_DATA_DIR` (where `users.db` and avatars are stored), `SERES_ALLOWED_HOSTS`
(extra hostnames allowed as request `Origin`, comma separated), `URL` (uptime heartbeat).

---

## 🔒 How the end-to-end encryption works

- **Your password never reaches the server in usable form.** The browser derives a master key with
  PBKDF2-SHA256 (600,000 iterations, random salt) and splits it with HKDF into an *auth hash*
  (sent to the server, stored with Argon2id) and a *key-wrapping key* (never leaves the device).
- **Identity keys:** on registration the browser creates a P-256 ECDH key pair (encryption) and a
  P-256 ECDSA key pair (signatures). The private keys are uploaded only after being encrypted with
  the key-wrapping key (AES-256-GCM). After login they are unlocked and stored in IndexedDB as
  *non-extractable* WebCrypto keys.
- **Messages:** every message gets a fresh AES-256-GCM key. That key is wrapped for each chat
  member with a pairwise key derived from ECDH + HKDF, and the whole envelope (chat, message id,
  sender, ciphertext, wrapped keys) is signed with the sender's ECDSA key. The server checks that
  a message is encrypted for exactly the current members, but can neither read nor forge it.
- **Groups:** new members only receive keys for messages sent after they joined.
- **Verification:** each chat shows a 60-digit security code (like WhatsApp/Signal). Compare it
  with your contact; contacts' key fingerprints are pinned on first use and you get a warning
  (and sending is blocked) if the server ever hands out a different key.
- **Limits:** this is not the Signal protocol – there is no forward secrecy (a stolen password +
  server database exposes old messages), and metadata (who chats with whom, when) is visible to
  the server. Messages from before v1.1 stay readable and are marked *not encrypted*.
- Forgetting your password means losing access to your encrypted history – there is no recovery.
