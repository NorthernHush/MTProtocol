<h1 align="center">
🔒 <b>MTProtocol</b> 🔒
</h1>

<h3 align="center">
<i>Anonymity. Security. Control</i>
</h3>

<p align="center"> 
<img src="https://img.shields.io/badge/Status-Open_Source-blue?style=for-the-badge&logo=github"/> 
<img src="https://img.shields.io/badge/Encryption-E2EE-green?style=for-the-badge&logo=lock"/> 
<img src="https://img.shields.io/badge/Protocol-Double_Ratchet-purple?style=for-the-badge&logo=cryptography"/>
</p>

# 🧩 MTProtocol - Cryptographic core of an anonymous P2P messenger

<p align="center"> 
🔒───🔐───🛡️───🕵️‍♂️───🧩<br> 
│&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;│&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;│& nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;│&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;│<br> 
🧩───🕵️‍♂️───🛡️───🔐───🔒<br> 
│&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;│&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;│& nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;│&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;│<br>
🔐───🛡️───🕵️‍♂️───🧩───🔒
</p>

> ✅ **This repository is public and intended for all developers, researchers, and enthusiasts interested in private and secure communications.**

**MTProtocol** is an open, highly secure implementation of the Double Ratchet protocol in C, designed as the cryptographic foundation for the anonymous P2P messenger **Mesh**.

The project focuses on:
- **Full control over data**: all encryption and key management operations occur locally.
- **Maximum resilience to compromise**: forward secrecy and post-compromise security by default.
- **Transparency and auditability**: open source code allows for independent security verification.

Technology stack:
- **C99** — for the cryptographic core and memory management
- **OpenSSL 3.0+** — for X25519, HKDF, ChaCha20-Poly1305
- **Python 3.6+** — for auxiliary tools: build (`meshprotocol.py`), testing, and debugging

This protocol is not just a library. It is a **privacy guarantee** built on the principles of openness and trust through verifiability.

MeshRatchet is a lightweight C library implementing a secure cryptographic messaging protocol with double ratcheting (forward secrecy) and post-compromise security. The library is designed for use in instant messaging apps, IoT devices, and other applications where confidentiality and integrity of communications are important.

> Version: v0.1
> Author: NorthernHush

---

## 🔒 Key Features

- Double Ratchet: Automatic key updates with each message.
- Forward Secrecy: Compromising a long-term key does not reveal past messages.
- Post-Compromise Security: Even if current keys are leaked, the session regains security over time. - **Integrity and Authentication**: Authenticated encryption (AEAD) via **ChaCha20-Poly1305**.
- **Flexible Configuration**: Configure message size, key refresh intervals, logging, and random number generation.
- **Secure Memory Wipe**: Sensitive data (keys, secrets) are cleared after use.
- **Serialization and Batch Operations** (optional).

---

## 🧰 Requirements

- **OpenSSL 3.0+** (for X25519, HKDF, ChaCha20-Poly1305)
- Python 3.6+
- C99 compiler or later
- POSIX-compliant system (for `time()`)

---

## 📦 Installation and Building

MeshRatchet comes with a convenient Python script, `meshprotocol.py`, which automates building the library and examples.

### Requirements
- Python 3.6+
- OpenSSL 3.0+ (with header files)
- C compiler (gcc/clang)

### Quick build
```bash
# Building the main library
python3 meshprotocol.py build

# Building with examples
python3 meshprotocol.py build --with-examples

# Installing on the system (optional)
sudo python3 meshprotocol.py install

# Checking dependencies
python3 meshprotocol.py check

# Running tests (if any)
python3 meshprotocol.py test

# Generating documentation
python3 meshprotocol.py docs

# Cleaning up build artifacts
python3 meshprotocol.py clean
```
> 💡 The script will automatically detect OpenSSL and set the compilation flags. If necessary, you can specify the path manually:
> `python3 meshprotocol.py build --openssl-path /usr/local/ssl`
## 🔐 Cryptographic Primitives

MeshRatchet is built on proven and modern cryptographic algorithms:

| Component | Algorithm | Purpose |
|---------------------|-----------------------------------------------|
| **Key Exchange** | `X25519` (Elliptic Curve DH) | Secure Shared Secret Negotiation |
| **Derivative Function** | `HKDF-SHA256` | Generate Cryptographic Keys from Secrets |
| **Encryption** | `ChaCha20-Poly1305` (AEAD) | Authenticated Message Encryption |
| **Ratchet Function** | `HMAC-SHA256` | One-Way Keychain Update |

All primitives comply with IETF and Signal Protocol recommendations.

---

## 📚 Public API

The library provides a simple and secure C API:

- **`mr_init()` / `mr_init_ex()`**
Initialize a context with default settings or user-defined parameters.

- **`mr_generate_key_pair()`**
Generate a new X25519 key pair (public + private key).

- **`mr_session_create()`**
Establish a secure session with the remote party based on public key exchange.

- **`mr_encrypt()` / `mr_decrypt()`**
Encrypt and decrypt messages with automatic key management and replay protection.

- **`mr_key_update()`**
Scheduled key updates (e.g., once every N messages).

- **`mr_emergency_key_update()`**
Emergency reset of all keys if a compromise is suspected.

- **`mr_get_session_info()`**
Retrieving session metadata: counters, ID, activity status.

- **`mr_error_string()`**
Converting error codes to human-readable strings for logging and debugging.

> 📌 A full description of types, structures, and return values ​​is in the [`meshratchet.h`](meshratchet.h) header file.

---

## 📄 License

MTProtocol is distributed under the proprietary **MIT LICENSE**.

- ✅ Free for research, education, and non-commercial use.
- 💼 Written permission required for commercial implementation.

---

## 🤝 Support and Feedback

We are open to collaboration and ready to help:

- **Vulnerability reports**: send them to Telegram with the subject **[SECURITY]**

> ⚠️ **Important**:
> **MTProtocol** **v0.1** is an **alpha version**, under active development.
> **Not recommended** for use in production environments without independent cryptographic auditing.
