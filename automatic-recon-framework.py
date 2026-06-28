import os
import nmap
import subprocess
import requests
import time
import urllib3
import platform
import json

if platform.system() == "Windows":
    print("This script must be run from WSL or Linux, not from Windows.")
    exit()

from pathlib import Path
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()
api_key = os.getenv("NVD_API_KEY")

BASE_DIR = Path(__file__).resolve().parent
wordlist = BASE_DIR / "wordlist" / "common.txt"
report = BASE_DIR / "reports" / "markdown.txt"
report.parent.mkdir(parents=True, exist_ok=True)

def to_wsl(path):
    path = Path(path).resolve()
    if platform.system() == "Windows":
        drive = path.drive[0].lower()
        rest = str(path).replace(path.drive, "").replace("\\", "/")
        return f"/mnt/{drive}{rest}"
    else:
        return str(path)

enum4linux_python = to_wsl(
    BASE_DIR / "tools" / "enum4linux-ng" / "venv" / "bin" / "python"
)

enum4linux_script = to_wsl(
    BASE_DIR / "tools" / "enum4linux-ng" / "enum4linux-ng.py"
)

if Path('reports/markdown.txt').exists():
    os.remove('reports/markdown.txt')

nm = nmap.PortScanner()

url = "192.168.x.x" ## URL OR IP ADD

nm.scan(f'{url}', arguments="-sV -sC -Pn")

ip = nm.all_hosts()[0]

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

if platform.system() == "Windows":
    enum4linux_cmd = ["wsl", enum4linux_python, enum4linux_script, "-A", f'{ip}']
    smbclient_cmd = ["wsl", "smbclient", "-L", f'//{ip}', "-N"]
else:
    enum4linux_cmd = [enum4linux_python, enum4linux_script, "-A", f'{ip}']
    smbclient_cmd = ["smbclient", "-L", f'//{ip}', "-N"]

enum4linux = subprocess.run(enum4linux_cmd, capture_output=True, text=True)
smbclient = subprocess.run(smbclient_cmd, capture_output=True, text=True)

i = 0
cpelist = []

for host in nm.all_hosts():
    print('Host: %s (%s)' % (host, nm[host].hostname()))
    print('State: %s' % nm[host].state())

    for protocol in nm[host].all_protocols():
        print('Protocol: %s' % protocol)

        lport = sorted(nm[host][protocol].keys())

        for port in lport:
            if nm[host][protocol][port]['state'] == "open":
                print('Port: %s \tState: %s' % (port, nm[host][protocol][port]['state']))
                cpelist.append(nm[host][protocol][port]['cpe'].split(':'))

i = 0

while i < len(cpelist):
    if cpelist[i] == ['']:
        cpelist.pop(i)
    else:
        i = i + 1
    
i = 0
for i in range(len(cpelist)):
    cpelist[i].insert(1, '2.3')

cpeurls = []
i = 0
for i in range(len(cpelist)):
    while len(cpelist[i]) < 14:
        cpelist[i].append('*')
    cpeurls.append(cpelist[i])

usableurls = []
for urls in cpeurls:
    my_str = ':'.join(urls).replace('/', '')
    usableurls.append(my_str)


responsesvuln = []
cve_ids = []
for usableurl in usableurls:
    responsevuln = requests.get(
        "https://api.vulncheck.com/v3/index/nist-nvd2",
        params={"cpeName": usableurl},
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
    )
    data = responsevuln.json()
    vulns = data.get("data", [])
    for vuln in vulns:
        cve_id = vuln.get("id", "N/A")
        cve_ids.append(cve_id)
    if responsevuln.status_code == 200:
        responsesvuln.append(responsevuln)
    else:
        print(f'Error: {responsevuln.status_code} for {usableurl}')

cve_ids = list(dict.fromkeys(cve_ids))

cve_details = []
searchsploit_details = []
for cve_id in cve_ids[:20]:
    responsescve = requests.get(
        f"https://cve.circl.lu/api/cve/{cve_id}",
        verify=False
    )
    cve_number = cve_id.replace("CVE-", "")
    searchsploit = subprocess.run(
        ["searchsploit", "--json", "--cve", cve_number],
        capture_output=True,
        text=True,
    )
    data = json.loads(searchsploit.stdout)
    exploits = data.get("RESULTS_EXPLOIT", [])
    searchsploit_details.append(exploits)

    
    if responsescve.status_code == 200:
        data = responsescve.json()
        cve_details.append(data)
    time.sleep(3)

with open(report, "w") as f:
    f.write("# Recon Report\n\n")
    
    f.write("## Nmap Scan\n\n")
    for host in nm.all_hosts():
        f.write(f"**Host:** {host} ({nm[host].hostname()})\n\n")
        f.write("| Port | State | Service | Version |\n")
        f.write("|------|-------|---------|----------|\n")
        for protocol in nm[host].all_protocols():
            for port in sorted(nm[host][protocol].keys()):
                state = nm[host][protocol][port]['state']
                service = nm[host][protocol][port]['name']
                version = nm[host][protocol][port]['version']
                f.write(f"| {port} | {state} | {service} | {version} |\n")
    
    f.write("\n## Gobuster\n\n")
    f.write(f"```\n{gobuster.stdout}\n```\n\n")
    
    f.write("## Enum4linux\n\n")
    f.write(f"```\n{enum4linux.stdout}\n```\n\n")
    
    f.write("## SMBclient\n\n")
    f.write(f"```\n{smbclient.stdout}\n```\n\n")
    
    f.write("## CVEs Found\n\n")
    for i, cve in enumerate(cve_details):
        cve_id = cve.get("cveMetadata", {}).get("cveId", "N/A")
        try:
            description = cve["containers"]["cna"]["descriptions"][0]["value"]
        except:
            description = "No description"
        try:
            score = cve["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"]
        except:
            try:
                score = cve["containers"]["cna"]["metrics"][0]["cvssV3_0"]["baseScore"]
            except:
                score = "N/A"
        
        f.write(f"### {cve_id}\n")
        f.write(f"**Score CVSS:** {score}\n\n")
        f.write(f"{description}\n\n")
        
        exploits = searchsploit_details[i] if i < len(searchsploit_details) else []
        if exploits:
            f.write("**Exploits disponibles:**\n\n")
            for exploit in exploits:
                f.write(f"- {exploit.get('Title', 'N/A')} — `{exploit.get('Path', 'N/A')}`\n")
            f.write("\n")
