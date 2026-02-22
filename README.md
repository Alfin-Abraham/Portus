# Portus — Secure LAN File Sharing

Portus is a self-hosted, local-network file sharing server built with **FastAPI** and **Uvicorn**. It runs directly from your machine and makes files instantly accessible to every device on your network — phones, tablets, laptops — through a clean browser UI, with no cloud services, no accounts, and no data leaving your LAN.

---

## Table of Contents

- [Features](#features)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Setup & Installation](#setup--installation)
  - [1. Clone the repository](#1-clone-the-repository)
  - [2. Install dependencies](#2-install-dependencies)
  - [3. Configure your PIN](#3-configure-your-pin)
  - [4. Generate SSL certificates (recommended)](#4-generate-ssl-certificates-recommended)
  - [5. Run the server](#5-run-the-server)
- [Accessing Portus](#accessing-portus)
- [iOS / iPadOS Setup](#ios--ipados-setup)
- [Supported File Types](#supported-file-types)
- [Security Overview](#security-overview)
- [Configuration Reference](#configuration-reference)
- [Platform Notes](#platform-notes)
- [License](#license)

---

## Features

- **HTTPS out of the box** — Generates a private Root CA and a signed server certificate using the `cryptography` library. No third-party CA required.
- **mDNS service discovery** — Registers itself on your LAN via Zeroconf so devices can reach it at `https://portus.local:6080` without configuring DNS.
- **PIN authentication** — Simple numeric PIN login loaded from a local `secrets.env` file. Sessions expire automatically after 12 minutes of inactivity.
- **Resumable chunked uploads** — Large files are transferred in sequential 3 MB chunks with a server-side SHA-256 integrity check on every upload. Supports files up to 5 GB.
- **Multi-file uploads** — Upload multiple files in a single request, with up to 3 concurrent uploads enforced server-side.
- **HTTP range request streaming** — Downloads and inline media playback both support byte-range requests, enabling seek-ahead video/audio streaming in the browser.
- **Real-time UI updates** — Server-Sent Events (SSE) push file-list refreshes and server shutdown notices to all connected clients instantly.
- **Upload cancellation** — In-progress uploads can be cancelled from the UI; partial files are cleaned up automatically.
- **Inline file viewer** — Images, videos, audio, PDFs, and text files open directly in the browser without downloading.
- **Dark / Light theme** — Persisted per-session; defaults to dark mode.
- **Automatic firewall management** — Opens and closes the required port on startup and shutdown for Windows (netsh) and Linux (UFW).
- **iOS `.mobileconfig` profile** — The SSL generator produces a ready-to-install Apple configuration profile that adds the Root CA to your device's trust store.
- **Cross-platform** — Runs on Windows, macOS, and Linux.

---

## Project Structure

```
Portus/
├── Portus.py               # FastAPI application & Uvicorn server entry point
├── Portus_SSL_genny.py     # SSL certificate & iOS mobileconfig generator
├── requirements.txt        # Python dependencies
├── secrets.env             # Your PIN (create this file — see Setup)
├── templates/
│   └── Portus.html         # Single-page browser UI (Tailwind CSS)
├── Portus_Dock/            # Auto-created — shared files are stored here
│   └── .uploads/           # Auto-created — temporary chunks during upload
└── Portus_Certificates/    # Auto-created by Portus_SSL_genny.py
    ├── root_key.pem        # Root CA private key  ⚠ keep private
    ├── root_cert.pem       # Root CA certificate (PEM)
    ├── root_cert.cer       # Root CA certificate (DER) — for manual installs
    ├── server_key.pem      # Server private key   ⚠ keep private
    ├── server_cert.pem     # Server certificate (PEM)
    └── root_ca.mobileconfig  # iOS/iPadOS trust profile
```

---

## Requirements

- Python 3.10 or later
- pip

Dependencies (installed via `requirements.txt`):

| Package | Version |
|---|---|
| fastapi | 0.129.0 |
| uvicorn | 0.41.0 |
| cryptography | 46.0.5 |
| python-multipart | 0.0.22 |
| aiofiles | 25.1.0 |
| Werkzeug | 3.1.5 |
| python-dotenv | 1.2.1 |
| pyOpenSSL | 25.3.0 |
| zeroconf | 0.148.0 |

---

## Setup & Installation

### 1. Clone the repository

```bash
git clone https://github.com/Alfin-Abraham/Portus.git
cd Portus
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure your PIN

Create a `secrets.env` file in the root `Portus/` directory:

```env
PIN=12345
```

Replace `12345` with any numeric PIN of your choice. This file is read at startup and is never transmitted.

### 4. Generate SSL certificates (recommended)

HTTPS is strongly recommended, especially for iOS devices which block non-HTTPS local servers by default.

```bash
python Portus_SSL_genny.py
```

This will generate all certificate files inside `Portus_Certificates/` and produce a `root_ca.mobileconfig` profile for iOS trust installation. Certificates are valid for **397 days** from the date of creation.

> **Keep `root_key.pem` and `server_key.pem` private.** These files are not required by clients and should never be shared.

### 5. Run the server

```bash
python Portus.py
```

If the SSL certificates are present, the server starts in HTTPS mode automatically. Otherwise it falls back to HTTP.

```
------------------------------------------------------------
Portus | Secure LAN File Sharing
------------------------------------------------------------

HTTPS mode enabled (SSL certificates found)

TO ACCESS FROM DEVICES ON YOUR NETWORK VISIT:
   https://portus.local:6080
```

Stop the server with `Ctrl + C`. The firewall rule and mDNS registration are cleaned up automatically on shutdown.

---

## Accessing Portus

Once the server is running, open a browser on any device connected to the same network and navigate to:

```
https://portus.local:6080
```

Enter your PIN to authenticate. Your session remains active for **12 minutes** of inactivity before requiring you to log in again.

> **Self-signed certificate warning:** Browsers will display a security warning on first visit. This is expected for self-signed certificates. You can dismiss it by clicking **"Show Details" → "Visit this website"** (Safari/iOS) or **"Advanced" → "Proceed"** (Chrome/Firefox). To eliminate the warning entirely on iOS, install the `.mobileconfig` profile (see below).

---

## iOS / iPadOS Setup

To trust the Portus Root CA on an iPhone or iPad and remove the certificate warning:

1. Copy `Portus_Certificates/root_ca.mobileconfig` to your device (via AirDrop, email, or by hosting it temporarily).
2. Open the file on your device and follow the prompts to **install the profile**.
3. Go to **Settings → General → About → Certificate Trust Settings**.
4. Enable **full trust** for the **Portus Root CA**.

After completing these steps, Safari and other browsers will trust the Portus server certificate without warnings.

---

## Supported File Types

Portus accepts uploads for the following file categories:

| Category | Extensions |
|---|---|
| Documents | `txt`, `rtf`, `pdf`, `doc`, `docx`, `xls`, `xlsx`, `ppt`, `pptx`, `md`, `csv`, `tsv` |
| Images | `png`, `jpg`, `jpeg`, `gif`, `webp`, `svg` |
| Video | `mp4`, `avi`, `mkv`, `mov`, `webm` |
| Audio | `mp3` |
| Archives | `zip`, `rar`, `7z`, `tar`, `gz`, `tgz` |
| Code | `py`, `js`, `ts`, `html`, `css`, `xml`, `json`, `yml`, `yaml`, `c`, `h`, `cpp`, `cs`, `php`, `rb`, `go`, `swift`, `sh`, `java` |
| Data | `db`, `sqlite`, `sqlite3`, `mdb`, `accdb`, `mdf`, `ldf`, `bson`, `parquet` |
| BI / Analytics | `pbix`, `pbit`, `pbip`, `twbx`, `twb`, `hyper`, `tds` |
| Apple | `mobileconfig` |

---

## Security Overview

| Mechanism | Detail |
|---|---|
| Transport security | TLS via self-signed certificate chain (Root CA → Server cert) |
| Authentication | Numeric PIN loaded from `secrets.env`, never stored in code |
| Session management | Server-side sessions with 12-minute inactivity timeout; session secret regenerated on every restart |
| File path validation | All paths resolved and verified to be within `Portus_Dock/` before any file operation |
| Filename sanitisation | Werkzeug `secure_filename` + `..` stripping to prevent directory traversal |
| File type allowlist | Only explicitly permitted extensions are accepted |
| Upload integrity | Running SHA-256 hash computed during transfer; returned to client on completion |
| Concurrent uploads | Capped at 3 simultaneous uploads via an asyncio semaphore |
| Max file size | 5 GB per file |
| Scope | LAN-only; no internet exposure by design |

> Portus is intended for trusted local networks. It is not hardened for exposure to the public internet.

---

## Configuration Reference

All constants are defined in the `Config` class in `Portus.py` and the `CertConfig` class in `Portus_SSL_genny.py`. Common values you may want to adjust:

| Setting | Default | Description |
|---|---|---|
| `Config.PORT` | `6080` | Port the server listens on |
| `Config.SESSION_TIMEOUT_MINUTES` | `12` | Inactivity timeout before session expiry |
| `Config.MAX_CONTENT_LENGTH` | `5 GB` | Maximum upload file size |
| `Config.MAX_CONCURRENT_UPLOADS` | `3` | Max simultaneous uploads |
| `Config.UPLOAD_CHUNK_SIZE` | `3 MB` | Chunk size for streaming uploads |
| `Config.DOWNLOAD_CHUNK_SIZE` | `3 MB` | Chunk size for streaming downloads |
| `Config.MDNS_DOMAIN` | `portus.local` | mDNS hostname advertised on the LAN (.local in hostname required) |
| `CertConfig.VALIDITY_DAYS` | `397` | Certificate validity period in days |
| `CertConfig.ROOT_KEY_SIZE` | `4096` | Root CA RSA key size (bits) |
| `CertConfig.SERVER_KEY_SIZE` | `2048` | Server RSA key size (bits) |

---

## Platform Notes

**Windows** — The server uses `WindowsSelectorEventLoopPolicy` for asyncio compatibility. Firewall rules are added and removed automatically via `netsh advfirewall`.

**Linux** — Firewall rules are managed via `sudo ufw`. You will be prompted for your sudo password if required.

**macOS** — Firewall rules are not managed automatically. If prompted, allow the connection via **Apple menu → System Settings → Network → Firewall**. Run `python Portus_SSL_genny.py` and install the `.mobileconfig` on any iOS devices to avoid certificate warnings in Safari.

---

## License

```
MIT License

Copyright (c) 2026 Alfin-Abraham

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
