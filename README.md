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
