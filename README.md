# automatic-recon-framework

> Automated penetration testing reconnaissance tool — Nmap → Gobuster → Enum4linux → SMBclient → CVE lookup → Exploit mapping

Built from scratch on Kali Linux. No GUI, no shortcuts. Everything runs from the terminal and outputs a clean Markdown report.

---

## What it does

1. **Nmap** — scans the target for open ports, services and versions (`-sV -sC -Pn`)
2. **Gobuster** — brute-forces hidden directories and files on the web server
3. **Enum4linux-ng** — enumerates SMB shares, users, groups, OS info and policies
4. **SMBclient** — lists accessible SMB shares anonymously
5. **CVE lookup** — queries [cve.circl.lu](https://cve.circl.lu) with the CPEs extracted from Nmap to find known vulnerabilities
6. **Searchsploit** — maps each CVE to available exploits in the Exploit-DB database
7. **Report** — generates a structured Markdown report in `reports/markdown.txt`

Only CVEs that have a known exploit in Exploit-DB are included in the final report — no noise.

---

## Requirements

- Kali Linux (or any Debian-based Linux)
- Python 3.10+
- The following tools installed and available in PATH:

```
nmap
gobuster
smbclient
searchsploit (exploitdb)
```

---

## Installation

### 1. Clone the repository with submodules

```bash
git clone --recurse-submodules https://github.com/222hustler/automatic-recon-framework.git
cd automatic-recon-framework
```

> The `--recurse-submodules` flag is required. Without it, the `tools/enum4linux-ng/` folder will be empty and the script will crash.

### 2. Install system dependencies

```bash
sudo apt update
sudo apt install nmap gobuster smbclient -y
```

### 3. Install searchsploit (Exploit-DB)

```bash
sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb
sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
```

### 4. Install Python dependencies

```bash
pip3 install python-nmap requests python-dotenv urllib3 --break-system-packages
```

### 5. Set up enum4linux-ng virtualenv

```bash
cd tools/enum4linux-ng
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
deactivate
cd ../..
```

### 6. Configure environment variables

```bash
cp .env.example .env
```

The `.env` file is optional — it was used for API keys in earlier versions. You can leave it empty.

---

## Usage

### Set your target

Open `automatic-recon-framework.py` and replace the IP on this line:

```python
url = "192.168.x.x"  ## URL OR IP ADD
```

### Run the script

```bash
python3 automatic-recon-framework.py
```

The script will print scan progress to the terminal and write the final report to:

```
reports/markdown.txt
```

> ⚠️ Only use this tool against machines you own or have explicit written permission to test. Tested against Metasploitable2 in an isolated VMware lab.

---

## Report structure

The generated `reports/markdown.txt` contains:

```
# Recon Report

## Nmap Scan
Table of open ports with service and version

## Gobuster
Hidden directories and files found

## Enum4linux
SMB enumeration — users, shares, OS info, policies

## SMBclient
Anonymous share listing

## CVEs Found
Only CVEs with a known exploit in Exploit-DB, with:
- CVE ID
- CVSS score
- Description
- Exploit paths (Metasploit modules, Python scripts, etc.)
```

---

## Common issues and fixes

### The script crashes immediately

Make sure you cloned with `--recurse-submodules`. Check that `tools/enum4linux-ng/enum4linux-ng.py` exists.

### `ModuleNotFoundError: No module named 'nmap'`

```bash
pip3 install python-nmap --break-system-packages
```

### `searchsploit: command not found`

```bash
sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb
sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
```

### CVEs Found section is empty

Two possible causes:

**1. Network issue** — the script can't reach cve.circl.lu. Check your internet connection:
```bash
curl "https://cve.circl.lu/api/search/vsftpd/vsftpd"
```
You should see a JSON response with CVE data.

**2. No CPEs detected** — Nmap didn't identify service versions. Make sure the target is up and reachable:
```bash
ping <target-ip>
```
If the target is unreachable, the CPE list will be empty and no CVE lookup will happen.

### Network disappears between eth0 and eth1 on Kali (VMware)

If you run Kali in VMware with a Host-Only interface (eth0) and a NAT interface (eth1), they can conflict. Fix:

```bash
sudo nmcli device connect eth1
sudo ip addr add 192.168.100.200/24 dev eth0 2>/dev/null
sudo ip link set eth0 up
sudo ip route add 192.168.100.0/24 dev eth0 2>/dev/null
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
```

Save this as `~/fix-routes.sh` and run it at the start of each session.

### Enum4linux takes very long or hangs

Normal on some targets — enum4linux-ng does a full SMB enumeration (`-A` flag). Let it run, it will finish.

---

## Lab setup (tested environment)

| Component | Details |
|-----------|---------|
| Attacker | Kali Linux in VMware |
| Target | Metasploitable2 in VMware |
| Network | VMware Host-Only (VMnet1) |
| Attacker IP | 192.168.100.200 |
| Target IP | 192.168.100.135 |

---

## Project structure

```
automatic-recon-framework/
├── automatic-recon-framework.py   # Main script
├── wordlist/
│   └── common.txt                 # Wordlist for Gobuster
├── tools/
│   └── enum4linux-ng/             # Git submodule
├── reports/                       # Generated reports (gitignored)
├── .env                           # API keys (gitignored)
├── .env.example                   # Template
├── .gitignore
└── .gitmodules
```

---

## Disclaimer

This tool is for educational purposes and authorized penetration testing only. Do not run it against systems you do not own or have explicit permission to test.
