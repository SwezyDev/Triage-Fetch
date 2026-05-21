<h1 align="center">🛡️ Triage-Fetch 🛡️</h1>

<p align="center">
  <a href="https://www.python.org" target="_blank"><img src="https://img.shields.io/badge/Language-Python-blue?style=for-the-badge&logo=python" /></a>
  <a href="https://tria.ge/docs/" target="_blank"><img src="https://img.shields.io/badge/API-Triage-brightgreen?style=for-the-badge" /></a>
  <a href="https://t.me/BotFather" target="_blank"><img src="https://img.shields.io/badge/Bot-Telegram-0088cc?style=for-the-badge&logo=telegram" /></a>
  <br>
  <code>Leave a ⭐ if you like this Repository</code>
</p>

---

# 🚀 Project Overview

**Triage-Fetch** is a malware intelligence automation tool that monitors the [Triage](https://tria.ge) API for newly detected malware samples. It automatically fetches detailed analysis reports, extracts key indicators, and delivers them to Telegram in real-time.

The application runs as a persistent listener, continuously polling Triage for new samples matching your configured criteria (malware families and/or tags), then processes and distributes analysis data through Telegram with structured reports and raw sample files.

> [!IMPORTANT]
> This tool requires valid **Triage API credentials (Researcher License)** and **Telegram Bot credentials** to function.
> Ensure you have proper authorization before using this tool.

---

## ✨ Features

- 🔍 **Automated Malware Monitoring** — Continuously polls Triage API for new samples matching your filters.
- 📊 **Comprehensive Analysis Extraction** — Automatically pulls and extracts:
  - Malware family and type
  - SHA256 and file hashes
  - File size and metadata
  - Threat scores and classifications
  - YARA rules matches
  - C2 addresses and network indicators
  - Behavioral analysis results
- 📤 **Telegram Integration** — Sends formatted analysis reports directly to your Telegram:
  - Direct messages to personal chats
  - Group messages with forum topic support
  - HTML formatted reports with detailed metadata
- 💾 **Local Report Storage** — Automatically saves:
  - Plain text analysis reports
  - JSON configuration files with extracted data
  - XOR-encrypted malware samples (`.malware` extension)
- 🎯 **Flexible Filtering** — Configure detection by:
  - Malware families (e.g., `xworm`, `emotet`, etc.)
  - Custom tags
  - Threat score thresholds
- 🤖 **Bot Command Handler** — Real-time Telegram commands:
  - `/get <sample_id>` — Fetch a specific sample on-demand
- 💾 **Persistent Tracking** — Automatically remembers processed samples:
  - Stores Malware Hashes in `seen_hashes.db`
  - Prevents reprocessing on restart
  - Resumes monitoring seamlessly after restarts
- ⏱️ **Configurable Polling** — Adjust polling interval and max results per poll
- 🎨 **Beautiful CLI** — Colored terminal output with timestamps and status indicators

---

## 🧭 How It Works

1. **Configuration**: Set up your Triage API key, Telegram bot token, and filtering criteria in `config.json`
2. **Start Listener**: Run `python main.py`
3. The tool will:
   - Query the Triage API for samples matching your filters
   - Mark current samples as baseline (won't reprocess existing ones)
   - Enter monitoring mode, polling at your configured interval
   - Automatically process and report any new samples via Telegram
   - Handle incoming bot commands for on-demand analysis
4. **Receive Updates**: Get notifications in your personal Telegram chat and/or group

> ✅ Fully automated — runs continuously once configured.

---

## 🧰 Requirements

- 🐍 Python **3.9+**
- 📦 Dependencies:
```bash
pip install requests colorama
```
- 🌐 Internet connection
- 🔑 **Triage API Key (Researcher License)** ([Create account at tria.ge](https://tria.ge/signup/researcher))
- 🤖 **Telegram Bot Token** ([Create via @BotFather](https://t.me/BotFather))

---

## ⚙️ Configuration

Edit `config.json` to configure the application:

```json
{
    "triage": {
        "api_key": "your_triage_api_key_here",
        "malware_family": ["xworm", "emotet"],
        "malware_tags": ["trojan", "ransomware"],
        "poll_interval": 30,
        "max_results": 50
    },
    "telegram": {
        "bot_token": "your_telegram_bot_token_here",
        "chat_id": "your_personal_chat_id",
        "group_id": "your_group_chat_id",
        "topic_id": "forum_topic_id_optional"
    }
}
```

**Configuration Options:**
- `api_key` — Your Triage API authentication token
- `malware_family` — Filter by malware family names (string or list)
- `malware_tags` — Filter by tags (array)
- `poll_interval` — Seconds between API polls (default: 30)
- `max_results` — Maximum results per poll (default: 50)
- `bot_token` — Your Telegram bot token (obtained from @BotFather)
- `chat_id` — Your personal Telegram chat ID (optional, for direct messages)
- `group_id` — Target group chat ID (optional, for group notifications)
- `topic_id` — Forum/topic ID within group (optional, for threaded messages)

---

## 📁 Repository Structure

```
├─ fetcher/ ➔ Core application modules
│  ├─ banner.py ➔ CLI banner and startup display
│  ├─ bot.py ➔ Telegram bot command handler (/get commands)
│  ├─ config.py ➔ Configuration file loader
│  ├─ formatter.py ➔ Data extraction and formatting utilities
│  ├─ sniper.py ➔ Automate something with the fetched C2s
│  ├─ telegram.py ➔ Telegram Bot API integration
│  └─ triage.py ➔ Triage API client (search, download, fetch)
├─ scripts/ ➔ Utility scripts for sample management
│  ├─ decode_sample.py ➔ Python Script to decode .malware files
│  ├─ delete_db.bat ➔ Windows batch script to delete the entire Seen Hashes Database
│  ├─ delete_db.sh ➔ Linux/macOS shell script to delete the entire Seen Hashes Database
│  ├─ delete_reports.bat ➔ Windows batch script to delete reports folder
│  └─ delete_reports.sh ➔ Linux/macOS shell script to delete reports folder
├─ config.json ➔ Configuration file (Triage API key, Telegram token, ...)
├─ main.py ➔ Main application logic and listener loop
├─ LICENSE ➔ MIT License file
└─ README.md ➔ This file
```

---

## 🚀 Usage

### 1. Install Dependencies
```bash
pip install requests colorama
```

### 2. Configure Credentials
```bash
# Edit config.json with your:
# - Triage API key
# - Telegram bot token
# - Chat IDs for notifications
# - Fetch Configurations
```

### 3. Run the Application
```bash
python main.py
```

### 4. Telegram Commands
Once running, interact with your Telegram bot:
```
/get <sample_id>   # Fetch a specific sample on-demand
```

---

## 🛠️ Scripts & Utilities

The `scripts/` folder contains helper utilities for managing reports and samples:

### `decode_sample.py`
Decodes XOR-encrypted `.malware` files back to their original binary format.

**Usage:**
```bash
# Linux/macOS
python ./scripts/decode_sample.py "reports/xworm/abc123.../filename.malware"

# Windows
python .\scripts\decode_sample.py "reports\xworm\abc123...\filename.malware"
```

**What it does:**
- Takes a `.malware` file as input
- XOR-decodes it with key `0xAA` (reverses the encryption applied during download)
- Outputs the original binary file (without the `.malware` extension)
- Example: `filename.malware` → `filename.exe`

> ⚠️ **Note**: The decoded file is the actual malware binary. Handle with care in isolated environments.

### `delete_reports.sh` / `delete_reports.bat`
Safely removes all downloaded reports and samples with confirmation prompt.

**Usage:**
```bash
# Linux/macOS
./scripts/delete_reports.sh

# Windows
.\scripts\delete_reports.bat
```

**What it does:**
- Prompts for confirmation before deletion
- Permanently deletes the entire `reports/` folder and all contents
- Useful for cleanup or starting fresh
- Requires manual confirmation (Ctrl+C to cancel)

### `delete_db.sh` / `delete_db.bat`
Safely delete your Seen Hashes Database with confirmation prompt.

**Usage:**
```bash
# Linux/macOS
./scripts/delete_db.sh

# Windows
.\scripts\delete_db.bat
```

**What it does:**
- Prompts for confirmation before deletion
- Permanently deletes the entire `seen_hashes.db` file
- Useful for cleanup or starting fresh
- Requires manual confirmation (Ctrl+C to cancel)


---

## 📋 Data Output

The application creates a structured directory hierarchy for reports:

```
reports/
├─ <malware_family>/
│  ├─ <sha256>/
│  │  ├─ report.txt         ➔ Plain text analysis report
│  │  ├─ config.json        ➔ Extracted metadata (JSON)
│  │  └─ <filename>.malware ➔ XOR-encrypted sample
│  └─ <malware_family>/
│     └─ ...
```

Each report includes:
- **Metadata**: File info, hashes, threat scores
- **Detection**: YARA rules, family classification
- **Network**: C2 addresses, domains, IPs
- **Behavior**: API calls, process analysis
- **Timestamps**: Submission and analysis dates

---

## 📺 Preview

[![Watch the demo](https://i.imgur.com/v98NxUF.jpeg)](https://www.youtube.com/watch?v=9iOe6xlAo5Y)

---

## 🔐 Security Notes

- ✅ The application XOR-encrypts downloaded samples with key `0xAA` (prevents accidental execution)
- 🔒 API keys are transmitted securely via HTTPS to Triage
- 📌 Telegram tokens should be kept private and rotated if exposed

---

## ⚖️ License

Distributed under the **MIT License**. See `LICENSE` for more information.

---

## 📝 Notes

- This tool is designed for **cybersecurity researchers and threat intelligence professionals**
- Only monitors **publicly available** malware analysis data from Triage
- Respects Triage API rate limits and polling intervals
- No data is stored or transmitted beyond your local system and configured Telegram chats

---

## 🚨 Disclaimer

This project is **intended for legitimate cybersecurity research and threat intelligence purposes only**. Users are responsible for compliance with all applicable laws and regulations. Unauthorized access to systems or excessive API usage is prohibited. The author assumes no liability for misuse of this tool.
