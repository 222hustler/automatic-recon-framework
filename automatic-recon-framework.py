import nmap
import subprocess
from pathlib import Path

## relative paths
BASE_DIR = Path(__file__).resolve().parent
wordlist = BASE_DIR / "wordlists" / "common.txt"
report = BASE_DIR / "reports" / "markdown.txt"
enum4linux_python = BASE_DIR / "tools" / "enum4linux-ng" / "venv" / "bin" / "python"
enum4linux_script = BASE_DIR / "tools" / "enum4linux-ng" / "enum4linux-ng.py"

## remove files
## import os
## os.remove('markdown.txt')

## scan target ports
nm = nmap.PortScanner()

url = "scanme.nmap.org"

print(f'{url}')

nm.scan(f'{url}', arguments="-sV -sC")
print(nm.csv())

## get ip of the scanned website
ip = nm.all_hosts()[0]
print(f'{ip}')

## scan hidden pages/dirs on a webserver
gobusturl = f'http://{url}'

gobuster = subprocess.run([
    "gobuster",
    "dir",
    "-u",
    f'{gobusturl}',
    "-w",
    str(wordlist),
],
    capture_output=True,
    text=True
)

print(gobuster.stdout)
print(gobuster.stderr)
print(gobuster.returncode)

## get target information
enum4linux = subprocess.run([
    "wsl",
    str(enum4linux_python),
    str(enum4linux_script),
    "-A",
    f'{ip}',
],
    capture_output=True,
    text=True
)

print(enum4linux.stdout)
print(enum4linux.stderr)
print(enum4linux.returncode)

## check for an smbclient
smbclient = subprocess.run([
    "wsl",
    "smbclient",
    "-L",
    f'//{ip}',
    "-N"
],
    capture_output=True,
    text=True
)

print(smbclient.stdout)
print(smbclient.stderr)
print(smbclient.returncode)

with open(report, "w") as f:
    f.write(f'{nm.csv}')
    f.write(f'{gobuster.stdout}')
    f.write(f'{enum4linux.stdout}')
    f.write(f'{smbclient.stdout}')

for host in nm.all_hosts():
    print('Host: %s (%s)' % (host, nm[host].hostname()))
    print('State: %s' % nm[host].state())
    for protocol in nm[host].all_protocols():
        print('Protocol: %s' % protocol)

        lport = sorted(nm[host][protocol].keys())
        for port in lport:
            if nm[host][protocol][port]['state'] == "open":
                print(port)
                print(nm[host][protocol][port]['state'])
                print(nm[host][protocol][port]['product'])
                print(nm[host][protocol][port]['version'])
                print(nm[host][protocol][port]['cpe'])