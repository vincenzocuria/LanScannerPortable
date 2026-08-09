# -*- coding: utf-8 -*-
import subprocess
import sys
import os

def build():
    print("Compilazione eseguibile portatile LanScanner.exe tramite PyInstaller...")
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--windowed",
        "--name=LanScanner",
        "--icon=app_icon.ico",
        "--add-data=oui_vendor.zlib;.",
        "--add-data=app_icon.ico;.",
        "--add-data=app_icon.png;.",
        "main.py"
    ]
    res = subprocess.run(cmd)
    if res.returncode == 0:
        exe_path = os.path.abspath("dist/LanScanner.exe")
        print(f"\nBuild completato con successo!\nEseguibile portatile generato in: {exe_path}")
    else:
        print("\nErrore durante la compilazione PyInstaller.")

if __name__ == "__main__":
    build()
