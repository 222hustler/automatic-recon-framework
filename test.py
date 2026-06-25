import nmap

nm = nmap.PortScanner()
nm.scan("scanme.nmap.org")
print(nm.csv())

for host in nm.all_hosts():
    print('Host: %s (%s)' % (host, nm[host].hostname()))
    print('State: %s' % nm[host].state())
    for protocol in nm[host].all_protocols():
        print('Protocol: %s' % protocol)

        lport = sorted(nm[host][protocol].keys())
        for port in lport:
            if nm[host][protocol][port]['state'] == "open":
                print('---------------------------------')
                print(port)
                print(nm[host][protocol][port]['state'])
                print(nm[host][protocol][port]['product'])
                print(nm[host][protocol][port]['version'])
                print(nm[host][protocol][port]['cpe'])
