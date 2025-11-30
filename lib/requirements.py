import subprocess
import os

def check_requirements():
    required_commands = ["vncviewer", "mitmweb", "qemu-img"]
    for cmd in required_commands:
        if not is_command_available(cmd):
            print(f"Missing required command: {cmd}")
            return False
    required_files = ["./db/GeoLite2-Country.mmdb", "./db/countries.json"]
    for file in required_files:
        if not os.path.exists(file):
            print(f"Missing required file: {file}")
            return False
    return True

def is_command_available(command):
    try:
        subprocess.run([command, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        return False