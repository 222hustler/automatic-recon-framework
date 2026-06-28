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

url = "192.168.100.135" ## URL OR IP ADD

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

enum4linux_cmd = [enum4linux_python, enum4linux_script, "-A", f'{ip}']
smbclient_cmd = ["smbclient", "-L", f'//{ip}', "-N"]

enum4linux = subprocess.run(enum4linux_cmd, capture_output=True, text=True)
smbclient = subprocess.run(smbclient_cmd, capture_output=True, text=True)

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
                cpe_raw = nm[host][protocol][port]['cpe']
                if cpe_raw:
                    cpelist.append(cpe_raw.split(':'))

# Remove empty entries
cpelist = [cpe for cpe in cpelist if cpe != ['']]
# Remove duplicates
cpelist = list({tuple(cpe): cpe for cpe in cpelist}.values())

# cpe format: ['cpe', '/a', 'vendor', 'product', 'version', ...]
# cpe[2] = vendor, cpe[3] = product

cve_ids = []
for cpe in cpelist:
    if len(cpe) >= 4:
        vendor = cpe[2]
        product = cpe[3]
        print(f"Searching CVEs for: {vendor}/{product}")
        url_search = f"https://cve.circl.lu/api/search/{vendor}/{product}"
        response = requests.get(url_search)
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            results = data.get("results", {})
            for source in ["cvelistv5", "nvd"]:
                for item in results.get(source, []):
                    cve_id = item[1].get("cveMetadata", {}).get("cveId", "N/A")
                    if cve_id != "N/A":
                        cve_ids.append(cve_id)
            print(f"CVEs found so far: {len(cve_ids)}")
        time.sleep(3)

cve_ids = list(dict.fromkeys(cve_ids))
print(f"Unique CVE IDs: {len(cve_ids)}")

cve_details = []
searchsploit_details = []
for cve_id in cve_ids:
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
    time.sleep(6)

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