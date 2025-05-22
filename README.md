# ⚡ injectx

**Asynchronous, high-speed SQL Injection scanner** built for recon, triage, and automation — not bloated, just deadly.

> 🚀  Fully async · HTTP/2 support · Header/Body/Param injection · Discord alerts · Proxy-ready

---

## 🔧 Features

- 🔍 Error-based, Boolean-based, and Time-based SQLi detection
- 🎯 Injects into:
  - Query parameters
  - POST/PUT/PATCH bodies
  - Headers (`User-Agent`, `X-Forwarded-For`, `X-Client-IP`)
- 🔁 Multi-method: GET, POST, PUT, PATCH, HEAD, OPTIONS
- 📡 Path fuzzing: `/admin/`, `/login`, `/search`, etc.
- 🔗 Proxy support (`--proxy`)
- 🚨 Discord webhook notifications (`--webhook`)
- ⚙️ Output as line-delimited JSON (`--out results.jsonl`)
- 🧠 Fingerprints DBMS (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)

---

## ⚙️ Install

```bash
pip install httpx[http2] typer loguru rich
```

---

## 🚀 Usage

```bash
# Single target
python scanner.py scan "http://example.com/page.php?id=1"

# Multiple targets
python scanner.py scan -f targets.txt

# With proxy and Discord alerting
python scanner.py scan -f targets.txt --proxy http://127.0.0.1:8080 --webhook https://discord.com/api/webhooks/...

# Save findings to file
python scanner.py scan -f targets.txt -o findings.jsonl
```

---

## ⚠️ Warning

This tool is built for educational, research, and authorized security testing only.  
**Never scan systems you don’t own or have explicit permission to test.**

---

## 🤘 Stay Fast, Stay Quiet

```plaintext
🩻  SQLi recon, the async way.
```

---

> Made for bug bounty hunters, red teamers, and anyone who’s tired of slow scans.
