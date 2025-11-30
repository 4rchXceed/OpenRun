# OpenRun

OpenRun is an open-source alternative to [AnyRun](https://any.run/), a popular online malware analysis sandbox. OpenRun allows users to analyze suspicious files and URLs in a controlled environment, providing insights into their behavior without risking harm to their own systems. It runs 100% locally, ensuring user privacy and data security.

## Features
- Local sandbox environment for malware analysis (KVM)
- You run the malware in the sandbox, and OpenRun collects:
    - Network traffic
    - Registry changes (suspicious activity, kinda crap for now)
    - Proccess creation/termination
    - HTTP/HTTPS requests (with mitmproxy, decrypts HTTPS traffic)
- Simple WebUI
- Simple installation
- Open-source and customizable
- AI-Mode (100% local, ollama) for single action summary of the malware behavior
- Supports Windows10/11 sandboxes
- IPTables-based network isolation (Internet access, but no LAN/host access)
- Snapshot support (revert the VM to a clean state after each run)

## Cons
- ONLY SUPPORTS LINUX HOSTS (for now)
- ONLY SUPPORTS WINDOWS GUESTS (for now)
- No public instance (you have to run it yourself)
- Limited features compared to AnyRun (no collaboration, no public reports, etc.)
- Still in early development, may have bugs and missing features

## NOTE ON SECURITY
Running malware, even in a sandboxed environment, carries inherent risks. While OpenRun is designed to isolate the malware from your host system, there is always a possibility of escape or unintended interactions. Users should exercise caution and ensure they understand the risks involved.

!! IF YOU DON'T KNOW WHAT YOU ARE DOING, DO NOT USE THIS SOFTWARE !!

!!! ALWAYS RUN OPENRUN UNDER A VPN TO AVOID IP LEAKS !!!

## Installation
See the [GETSTARTED.md](docs/GETSTARTED.md) for detailed installation instructions.

## Usage
See the [USAGE.md](docs/USAGE.md) for detailed usage instructions.

## TODO/Roadmap (if I ever get time)
See the [TODO.md](docs/TODO.md) for the current roadmap and planned features.

## Issues/Contributing
If you encounter any issues or have suggestions for improvements, please open an issue!

## Files that are not mine:
db/msft-public-ips.csv: List of Microsoft public IPs, used to ignore benign traffic to Microsoft services. Source: https://www.microsoft.com/en-us/download/details.aspx?id=53602
Geolite2 database: Used for IP geolocation. Source: https://git.io/GeoLite2-Country.mmdb

## License
This project is licensed under the 3-Clause BSD License. See the [LICENSE](LICENSE) file for details.

Thanks 🩵