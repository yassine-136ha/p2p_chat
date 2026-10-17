# 🛡️ P2P Encrypted Chat System in Rust

A decentralized, zero-persistence, peer-to-peer (P2P) secure messaging system built in **Rust**, leveraging **`libp2p`** and **Tor Onion Services (v3)** for absolute metadata anonymity and end-to-end encryption.

---

## 🚀 Key Features

* **True Decentralization:** Operates completely peer-to-peer with zero central servers or intermediate relays.
* **Tor Metadata Anonymity:** Integrates seamlessly with Tor V3 Hidden Services over SOCKS5, hiding both parties' IP addresses and connection metadata.
* **Military-Grade E2EE (Sealed Boxes):** Uses `X25519` ephemeral key exchange combined with `XChaCha20-Poly1305` and `Argon2` local key protection.
* **Zero-Persistence Design:** Messages are decrypted silently; no plaintext logs or chat history are ever written to disk.
* **Termux / Mobile Ready:** Fully compatible and optimized to run directly on Android devices via Termux.

---

## 🛠️ Prerequisites & Stack

* **Rust (Edition 2021+)**
* **Tor Daemon** (running locally for onion routing)
* **Termux** (if running on Android)

---

## ⚙️ Quick Start & Installation

1. **Clone the Repository:**
   ```bash
   git clone [https://github.com/yassine-136ha/p2p_chat.git](https://github.com/yassine-136ha/p2p_chat.git)
   cd p2p_chat

![Termux Execution Screenshot](https://raw.githubusercontent.com/yassine-136ha/p2p_chat/main/Screenshot_2026-10-17-17-01-53-051_com.miui.gallery.jpg)



ome to Termux!



Docs:       https://termux.dev/docs
Donate:     https://termux.dev/donate
Community:  https://termux.dev/community

Working with packages:

 - Search:  pkg search <query>
 - Install: pkg install <package>
 - Upgrade: pkg upgrade

Subscribing to additional repositories:

 - Root:    pkg install root-repo
 - X11:     pkg install x11-repo

For fixing any repository issues,
try 'termux-change-repo' command.

Report issues at https://termux.dev/issues
~/p2p_chat_1 $ cd
~ $ cd ~/p2p_chat_2 && TOR_HS_DIR=$PREFIX/var/lib/tor/chat_2 CHAT_TOR=1 ./p2p_chat
== Decentralized encrypted P2P chat (libp2p + E2E) ==

Identity
  1. Create new identity
  2. Load existing identity from file
Choose a number: 1
Password to protect your key: [hidden]
[✓] Key saved (encrypted) to node_identity.key
--------------------------------------------------
🔑 Your public key (share it): 96039f5330962ad7d9ec866628402d4f69314c26994ce08d25809e9fb32c51cf
🌐 PeerId: 12D3KooWKuxXXTJsPJVDt3pLyMqCH3zfq4RunrmzgBQEEQJPWLZU
--------------------------------------------------
Listen port [8001]: 8002
[tor] Listening on 127.0.0.1 only. Add to torrc:
      HiddenServiceDir <dir>/chat_service/
      HiddenServicePort 8002 127.0.0.1:8002
[tor] Your address to share: hi7u2zdmi3ajetxzgecjjvphzc5d27r7vhhblpnwfqvsvqgaw4us5gid.onion:8002 12D3KooWKuxXXTJsPJVDt3pLyMqCH3zfq4RunrmzgBQEEQJPWLZU
[*] Listening on /ip4/127.0.0.1/tcp/8002

--- Menu ---
  1. Show my key and PeerId
  2. Discovered peers
  3. Advertise my node
  4. Send encrypted message
  5. Dial a peer manually (multiaddr)
  6. Quit
Choose a number: 5
Peer address: xxxx.onion:8001 [optional PeerId]: 5qcj6ps6zu32ak26pmaz43levz6g2kbtfiluayxjasc32svszabmc4yd.onion:8001 12D3KooWF4mB3m1d2cNQCiZfdZ4oz8DywdBto1KK2MYYwE1PnuGp
[tor] Connecting via Tor (may take up to a minute)...

--- Menu ---
  1. Show my key and PeerId
  2. Discovered peers
  3. Advertise my node
  4. Send encrypted message
  5. Dial a peer manually (multiaddr)
  6. Quit
Choose a number:
[+] New peer: 12D3KooWF4mB3m1d2cNQCiZfdZ4oz8DywdBto1KK2MYYwE1PnuGp
    Key: 4dfa93fc307edaeb91ccad7a6b1346cf7a32ed37cb3816ac7e738d02989e0c8d












ome to Termux!

Docs:       https://termux.dev/docs
Donate:     https://termux.dev/donate
Community:  https://termux.dev/community

Working with packages:

 - Search:  pkg search <query>
 - Install: pkg install <package>
 - Upgrade: pkg upgrade

Subscribing to additional repositories:

 - Root:    pkg install root-repo
 - X11:     pkg install x11-repo

For fixing any repository issues,
try 'termux-change-repo' command.

Report issues at https://termux.dev/issues
~ $ cd ~/p2p_chat_1 && TOR_HS_DIR=$PREFIX/var/lib/tor/chat_1 CHAT_TOR=1 ./p2p_chat
== Decentralized encrypted P2P chat (libp2p + E2E) ==

Identity
  1. Create new identity
  2. Load existing identity from file
Choose a number: 1
Password to protect your key: [hidden]
[✓] Key saved (encrypted) to node_identity.key
--------------------------------------------------
🔑 Your public key (share it): 4dfa93fc307edaeb91ccad7a6b1346cf7a32ed37cb3816ac7e738d02989e0c8d
🌐 PeerId: 12D3KooWF4mB3m1d2cNQCiZfdZ4oz8DywdBto1KK2MYYwE1PnuGp
--------------------------------------------------
Listen port [8001]: 8001
[tor] Listening on 127.0.0.1 only. Add to torrc:
      HiddenServiceDir <dir>/chat_service/
      HiddenServicePort 8001 127.0.0.1:8001
[tor] Your address to share: 5qcj6ps6zu32ak26pmaz43levz6g2kbtfiluayxjasc32svszabmc4yd.onion:8001 12D3KooWF4mB3m1d2cNQCiZfdZ4oz8DywdBto1KK2MYYwE1PnuGp

--- Menu ---
  1. Show my key and PeerId
  2. Discovered peers
  3. Advertise my node
  4. Send encrypted message
  5. Dial a peer manually (multiaddr)
  6. Quit
Choose a number: [*] Listening on /ip4/127.0.0.1/tcp/8001

[!] Invalid choice

--- Menu ---
  1. Show my key and PeerId
  2. Discovered peers
  3. Advertise my node
  4. Send encrypted message
  5. Dial a peer manually (multiaddr)
  6. Quit
Choose a number:
[+] New peer: 12D3KooWKuxXXTJsPJVDt3pLyMqCH3zfq4RunrmzgBQEEQJPWLZU
    Key: 96039f5330962ad7d9ec866628402d4f69314c26994ce08d25809e9fb32c51cf





Choose a number: 5
Peer address: xxxx.onion:8001 [optional PeerId]: 5qcj6ps6zu32ak26pmaz43levz6g2kbtfiluayxjasc32svszabmc4yd.onion:8001 12D3KooWF4mB3m1d2cNQCiZfdZ4oz8DywdBto1KK2MYYwE1PnuGp
[tor] Connecting via Tor (may take up to a minute)...

--- Menu ---
  1. Show my key and PeerId
  2. Discovered peers
  3. Advertise my node
  4. Send encrypted message
  5. Dial a peer manually (multiaddr)
  6. Quit
Choose a number:
[+] New peer: 12D3KooWF4mB3m1d2cNQCiZfdZ4oz8DywdBto1KK2MYYwE1PnuGp
    Key: 4dfa93fc307edaeb91ccad7a6b1346cf7a32ed37cb3816ac7e738d02989e0c8d

──────── Encrypted message received ────────
From: 12D3KooWF4mB3m1d2cNQCiZfdZ4oz8DywdBto1KK2MYYwE1PnuGp
cv
──────────────────────────────────


2. Discovered peers
  3. Advertise my node
  4. Send encrypted message
  5. Dial a peer manually (multiaddr)
  6. Quit
Choose a number:
[+] New peer: 12D3KooWKuxXXTJsPJVDt3pLyMqCH3zfq4RunrmzgBQEEQJPWLZU
    Key: 96039f5330962ad7d9ec866628402d4f69314c26994ce08d25809e9fb32c51cf
4
Recipient public key (hex): 96039f5330962ad7d9ec866628402d4f69314c26994ce08d25809e9fb32c51cf
Message: cv
[✓] Sent encrypted (no local copy)

--- Menu ---
  1. Show my key and PeerId
  2. Discovered peers
  3. Advertise my node
  4. Send encrypted message
  5. Dial a peer manually (multiaddr)
  6. Quit
Choose a number:

