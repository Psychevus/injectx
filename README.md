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

---

## 📄 License

MIT License

```
MIT License

Copyright (c) 2025 Psychevus

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

---

## 🤝 Contributing

Contributions are welcome and appreciated!  
To contribute:

1. Fork the project
2. Create your feature branch (`git checkout -b feature/YourFeature`)
3. Commit your changes (`git commit -m 'Add awesome feature'`)
4. Push to the branch (`git push origin feature/YourFeature`)
5. Open a Pull Request

Please follow clean code practices and include meaningful commit messages.

---

## 📫 Contact

Created and maintained by **[@Psychevus](https://github.com/Psychevus)**  
For feedback or feature requests, feel free to open an issue or contact via GitHub.

