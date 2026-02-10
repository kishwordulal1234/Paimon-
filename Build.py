#!/usr/bin/env python3
"""
PyInstaller Build Script for Crocell
Builds standalone executables for Windows, Linux, and macOS

Usage:
    python build.py

Output:
    - dist/crocell.exe (Windows)
    - dist/crocell (Linux/macOS)
"""

import os
import sys
import subprocess
import platform

def build_executable():
    """Build standalone executable using PyInstaller"""
    
    print("=" * 60)
    print("Crocell PyInstaller Build Script")
    print("=" * 60)
    print(f"Platform: {platform.system()}")
    print(f"Python: {sys.version}")
    print("=" * 60)
    
    # Check if PyInstaller is installed
    try:
        import PyInstaller
        print(f"✓ PyInstaller {PyInstaller.__version__} found")
    except ImportError:
        print("✗ PyInstaller not found!")
        print("  Install with: pip install pyinstaller")
        sys.exit(1)
    
    # Check if source file exists
    if not os.path.exists("crocell_cross_platform.py"):
        print("✗ crocell_cross_platform.py not found!")
        sys.exit(1)
    
    print("✓ Source file found")
    print()
    
    # PyInstaller command
    cmd = [
        "pyinstaller",
        "--onefile",                    # Single executable file
        "--name=crocell",               # Output name
        "--clean",                      # Clean PyInstaller cache
        "--noconfirm",                  # Overwrite without asking
    ]
    
    # Platform-specific options
    if platform.system() == "Windows":
        cmd.extend([
            "--noconsole",              # Hide console window on Windows
            "--icon=NONE",              # No icon (can add custom icon here)
        ])
    
    # Add source file
    cmd.append("crocell_cross_platform.py")
    
    print("Building executable...")
    print(f"Command: {' '.join(cmd)}")
    print()
    
    try:
        # Run PyInstaller
        result = subprocess.run(cmd, check=True)
        
        print()
        print("=" * 60)
        print("✓ Build successful!")
        print("=" * 60)
        
        # Show output location
        if platform.system() == "Windows":
            exe_path = "dist\\crocell.exe"
        else:
            exe_path = "dist/crocell"
        
        if os.path.exists(exe_path):
            file_size = os.path.getsize(exe_path) / (1024 * 1024)
            print(f"Executable: {exe_path}")
            print(f"Size: {file_size:.2f} MB")
            print()
            print("IMPORTANT: Set environment variables before running:")
            print("  export CROCELL_BOT_TOKEN='your_bot_token'")
            print("  export CROCELL_CHAT_ID='your_chat_id'")
            print()
            print("Or on Windows:")
            print("  set CROCELL_BOT_TOKEN=your_bot_token")
            print("  set CROCELL_CHAT_ID=your_chat_id")
        else:
            print(f"✗ Executable not found at {exe_path}")
            sys.exit(1)
        
    except subprocess.CalledProcessError as e:
        print()
        print("=" * 60)
        print("✗ Build failed!")
        print("=" * 60)
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    build_executable()

