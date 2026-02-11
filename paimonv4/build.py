"""
Build Script for Crocell - Cross-Platform
Creates standalone executables for Windows, macOS, and Linux
"""
import os
import sys
import platform
import subprocess

PLATFORM = platform.system()

def build_windows():
    """Build Windows .exe"""
    print("Building Windows executable...")
    
    cmd = [
        "pyinstaller",
        "--onefile",                    # Single executable
        "--noconsole",                  # No console window
        "--name", "crocell",            # Output name
        "--icon", "NONE",               # No icon (can add custom)
        "--clean",                      # Clean build
        "--noconfirm",                  # Overwrite without asking
        
        # Hidden imports
        "--hidden-import", "win32crypt",
        "--hidden-import", "pycryptodome",
        "--hidden-import", "Crypto.Cipher.AES",
        "--hidden-import", "requests",
        "--hidden-import", "psutil",
        
        # Add data files if needed
        # "--add-data", "config.json;.",
        
        # UPX compression (optional, requires upx installed)
        # "--upx-dir", "path/to/upx",
        
        "crocell_production.py"
    ]
    
    subprocess.run(cmd, check=True)
    print("\n✅ Windows build complete: dist/crocell.exe")


def build_macos():
    """Build macOS .app"""
    print("Building macOS application...")
    
    cmd = [
        "pyinstaller",
        "--onefile",
        "--windowed",                   # No terminal window
        "--name", "crocell",
        "--clean",
        "--noconfirm",
        
        # Hidden imports
        "--hidden-import", "pycryptodome",
        "--hidden-import", "Crypto.Cipher.AES",
        "--hidden-import", "requests",
        "--hidden-import", "psutil",
        "--hidden-import", "keyring",
        
        "crocell_production.py"
    ]
    
    subprocess.run(cmd, check=True)
    print("\n✅ macOS build complete: dist/crocell.app")


def build_linux():
    """Build Linux binary"""
    print("Building Linux binary...")
    
    cmd = [
        "pyinstaller",
        "--onefile",
        "--name", "crocell",
        "--clean",
        "--noconfirm",
        
        # Hidden imports
        "--hidden-import", "pycryptodome",
        "--hidden-import", "Crypto.Cipher.AES",
        "--hidden-import", "requests",
        "--hidden-import", "psutil",
        "--hidden-import", "keyring",
        
        "crocell_production.py"
    ]
    
    subprocess.run(cmd, check=True)
    print("\n✅ Linux build complete: dist/crocell")


def main():
    print("="*60)
    print("Crocell Build Script - Production Ready")
    print("="*60)
    print(f"Platform: {PLATFORM}")
    print()
    
    # Check if PyInstaller is installed
    try:
        import PyInstaller
    except ImportError:
        print("❌ PyInstaller not found!")
        print("Install it with: pip install pyinstaller")
        sys.exit(1)
    
    # Check if source file exists
    if not os.path.exists("crocell_production.py"):
        print("❌ crocell_production.py not found!")
        print("Make sure you're in the correct directory")
        sys.exit(1)
    
    # Build based on platform
    try:
        if PLATFORM == "Windows":
            build_windows()
        elif PLATFORM == "Darwin":  # macOS
            build_macos()
        elif PLATFORM == "Linux":
            build_linux()
        else:
            print(f"❌ Unsupported platform: {PLATFORM}")
            sys.exit(1)
        
        print("\n" + "="*60)
        print("Build completed successfully!")
        print("="*60)
        print("\nOutput location: dist/")
        print("\nNOTE: Test the executable before deployment!")
        
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Build failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
