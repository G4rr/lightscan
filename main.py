#!/usr/bin/env python3
# Purpose: A simple scanner
# Author: me

import os
import json
import sys
import time
import ipaddress
import xml.etree.ElementTree as ET
import hashlib

from datetime import datetime
from scapy.all import *


# check if the script is running as root
if os.geteuid() != 0:
    print("This script must be run as root")
    sys.exit(1)

# Read filepath from command line arguments
if len(sys.argv) != 2:
    print("Usage: python3 main.py <domain_file>")
    sys.exit(1)


CLOUDFLARE_IP4_FILTER = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22"
]

CLOUDFLARE_IP6_FILTER = [
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32"
]

PRIVATE_IP4_FILTER = [
    "10.0.0.0/8",
    "127.0.0.0/8",
    "172.32.0.0/16",
    "100.64.0.0/10",
    "192.168.0.0/16"
]

tmp_reports = "tmp/reports"
if not os.path.exists(tmp_reports):
    print("Creating `tmp/reports` directory")
    os.makedirs(tmp_reports)
else:
    print("Cleaning `tmp/reports` directory")
    os.system(f"rm -rf {tmp_reports}/*")


domain_file = sys.argv[1]

results = {
}

dns_server_ip = "8.8.8.8"
dns_types = ["A", "CNAME", "MX", "NS", "PTR", "SOA", "TXT", "AAAA", "SRV", "DNSKEY", "DS", "NSEC", "TLSA", "CAA", "SPF"]
#dns_types = ["A", "CNAME"]


with open('ports/100.txt', 'r') as file:
    tcp_ports = file.readlines()

with open(domain_file, 'r') as file:
    domains = file.readlines()

for domain_name in domains:
    domain_name = domain_name.strip()
    dns_data = {}
    results[domain_name] = {
        "dns_data": dns_data,
        "ips": {}
    }
    
    for dns_type in dns_types:
        cmd = f"dig @{dns_server_ip} {domain_name} {dns_type} +short"
        print(f"Running command: {cmd}")
        output = os.popen(cmd).read()
        if output:
            dns_data[dns_type] = []
            for line in output.split('\n'):
                if line:
                    if dns_type == "A" or dns_type == "AAAA":
                        # check is the line vaild IP address
                        try:
                            ipaddress.ip_address(line)
                            dns_data[dns_type].append(line)
                        except ValueError:
                            print(f"ERROR: {line} is not a valid IP address format. Skipping...")
                            continue
                    else:
                        dns_data[dns_type].append(line)

            print(f"Output: {output}")
        time.sleep(.1)
    
    print(f"Finished DNS resolving scanning {domain_name}")

print("Finished DNS resolving")
print(f"DEBUG Results: {results}\n\n")

with open(f'{tmp_reports}/results.json', 'w') as outfile:
    json.dump(results, outfile, indent=4)

sys.exit(0)

for domain_name in results:
    dns_data = results[domain_name]["dns_data"]
    if "A" in dns_data:
        for i_ip in dns_data["A"]:
            # Check IP version
            i_ip = i_ip.strip()
            print(f"Checking IP version for {i_ip, type(i_ip)}")
            if ipaddress.ip_address(i_ip).version == 4:
                results[domain_name]["ips"][i_ip] = {
                    "status": "open",
                    "service": None,
                    "version": "ipv4",
                    "ports": {},
                    "last_detected": datetime.strftime(datetime.now(), "%Y-%m-%d:%H-%M-%S")
                }

                # check if the IP is a cloudflare IP CIDRs
                for cf_ip4_cidr in CLOUDFLARE_IP4_FILTER:
                    if ipaddress.ip_address(i_ip) in ipaddress.ip_network(cf_ip4_cidr):
                        print(f"{i_ip} is a Cloudflare IP. Skipping...")
                        results[domain_name]["ips"][i_ip] = {"status": "filtered",
                                                            "service": "cloudflare",
                                                            "last_detected": datetime.strftime(datetime.now(), "%Y-%m-%d:%H-%M-%S")}
                        break
            elif ipaddress.ip_address(i_ip).version == 6:
                results[domain_name]["ips"][i_ip] = {
                    "status": "open",
                    "service": None,
                    "version": "ipv6",
                    "ports": {},
                    "last_detected": datetime.strftime(datetime.now(), "%Y-%m-%d:%H-%M-%S")
                }
                for cf_ip6_cidr in CLOUDFLARE_IP6_FILTER:
                    if ipaddress.ip_address(i_ip) in ipaddress.ip_network(cf_ip6_cidr):
                        print(f"{i_ip} is a Cloudflare IP. Skipping...")
                        results[domain_name]["ips"][i_ip] = {"status": "filtered",
                                                            "service": "cloudflare",
                                                            "last_detected": datetime.strftime(datetime.now(), "%Y-%m-%d:%H-%M-%S")}
                        break
            else:
                print(f"ERROR: {i_ip} is not a valid IP address format. Skipping...")
                results[domain_name]["ips"][i_ip] = {"status": "invalid",
                                                    "service": "",
                                                    "last_detected": datetime.strftime(datetime.now(), "%Y-%m-%d:%H-%M-%S")}
                continue

ip_scan_history = {}

# Masscan for open ports
print("\n\n")
print("-"*100)
print("Start port scanning for A records")
for domain_name in results:
    for i_ip in results[domain_name]["ips"]:
        if results[domain_name]["ips"][i_ip]["status"] == "open":
            if i_ip in ip_scan_history:
                print(f"{i_ip} has already been scanned for open ports. Skipping...")
                results[domain_name]["ips"][i_ip] = ip_scan_history[i_ip]
            else:
                ip = IP(dst=i_ip)
                print(f"Scanning {i_ip} for open ports")
                for port in tcp_ports:
                    port = int(port.strip())
                    tcp = TCP(sport=RandShort(), dport=port, flags="A") # flags="A" for ACK scan
                    pkt = ip/tcp
                    resp = sr1(pkt, timeout=.7)

                    if resp:
                        print(f"{i_ip}:{port} is open")
                        results[domain_name]["ips"][i_ip]["ports"][port] = {"status": "open",
                                                                            "protocol": "tcp",
                                                                            "service": "",
                                                                            "product": "",
                                                                            "version": "",
                                                                            "extrainfo": "",
                                                                            "ostype": "",                        
                                                                            "last_detected": datetime.strftime(datetime.now(), "%Y-%m-%d:%H-%M-%S")}
                    else:
                        continue
                ip_scan_history[i_ip] = results[domain_name]["ips"][i_ip]
    
    # save tmp results
    with open(f'{tmp_reports}/results_{domain_name}.json', 'w') as outfile:
        json.dump(results, outfile, indent=4)


print("Finished port scanning for A records")
print(f"DEBUG Results: {results}\n\n")

# IP NMAP for detected open ports
if not os.path.exists("reports"):
    print("Creating `reports` directory")
    os.makedirs("reports")
if not os.path.exists("reports/nmap"):
    print("Creating `reports/nmap` directory")
    os.makedirs("reports/nmap")

ip_scan_history = {}

print("\n\n")
print("-"*100)
print("Start NMAP scanning for open ports")
for domain_name in results:
    if i_ip in ip_scan_history:
        print(f"{i_ip} has already been scanned for open ports. Skipping...")
        results[domain_name]["ips"][i_ip] = ip_scan_history[i_ip]
    for i_ip in results[domain_name]["ips"]:
        if not os.path.exists(f"reports/nmap/{i_ip}"):
            os.makedirs(f"reports/nmap/{i_ip}")
        if results[domain_name]["ips"][i_ip]["status"] == "open":
            open_ports = results[domain_name]["ips"][i_ip]["ports"]
            if not open_ports:
                print(f"DEBUG: No open ports for {i_ip}. Skipping NMAP scan")
                continue
            open_ports = ','.join(str(port) for port in open_ports)
            print(f"DEBUG: Open ports for {i_ip}: {open_ports}")
            print(f"Running NMAP for {i_ip}")
            nmap_cmd = f"nmap -sV -sC -Pn -T4 -p{open_ports} -oX reports/nmap/{i_ip}/{i_ip}.xml {i_ip}"
            print(f"DEBUG: Running Nmap command: {nmap_cmd}")
            os.system(nmap_cmd)
            
            # Parse NMAP XML report
            
            print(f"DEBUG: Parsing NMAP XML report for {i_ip}")
            with open(f"reports/nmap/{i_ip}/{i_ip}.xml", 'r') as file:
                nmap_report = file.read()

            root = ET.fromstring(nmap_report)
            for host in root.findall('host'):
                for port in host.findall('ports/port'):
                    port_id = port.get('portid')
                    service = port.find('service').get('name') if port.find('service').get('name') else None
                    product = port.find('service').get('product') if port.find('service').get('product') else None
                    version = port.find('service').get('version') if port.find('service').get('version') else None
                    extra_info = port.find('service').get('extrainfo') if port.find('service').get('extrainfo') else None
                    os_type = port.find('service').get('ostype') if port.find('service').get('ostype') else None
            
                    ssl = port.find('script[@id="ssl-cert"]')
                    ssl_data = {}
                    if ssl:
                        print(f"SSL Cert: {ssl.get('output')}")
                        ssl_cert_subject = ssl.find('table[@key="subject"]/elem[@key="commonName"]').text
                        ssl_cert_issuer = ssl.find('table[@key="issuer"]/elem[@key="commonName"]').text
                        ssl_cert_pubkey_type = ssl.find('table[@key="pubkey"]/elem[@key="type"]').text
                        ssl_cert_pubkey_bits = ssl.find('table[@key="pubkey"]/elem[@key="bits"]').text
                        ssl_cert_validity = ssl.find('table[@key="validity"]')
                        ssl_cert_validity_notbefore = ssl_cert_validity.find('elem[@key="notBefore"]').text
                        ssl_cert_validity_notafter = ssl_cert_validity.find('elem[@key="notAfter"]').text
                        ssl_cert_fingerprint_md5 = ssl.find('elem[@key="md5"]').text
                        ssl_cert_fingerprint_sha1 = ssl.find('elem[@key="sha1"]').text
                        ssl_cert_pem = ssl.find('elem[@key="pem"]').text

                        ssl_data = {
                            "subject": ssl_cert_subject,
                            "issuer": ssl_cert_issuer,
                            "pubkey": {
                                "type": ssl_cert_pubkey_type,
                                "bits": ssl_cert_pubkey_bits
                            },
                            "validity": {
                                "notBefore": ssl_cert_validity_notbefore,
                                "notAfter": ssl_cert_validity_notafter
                            },
                            "fingerprint": {
                                "md5": ssl_cert_fingerprint_md5,
                                "sha1": ssl_cert_fingerprint_sha1
                            },
                            "pem": ssl_cert_pem
                        }
                        results[domain_name]["ips"][i_ip]["ports"][int(port_id)] = {
                            "status": "open",
                            "protocol": "tcp",
                            "service": service,
                            "product": product,
                            "version": version,
                            "extrainfo": extra_info,
                            "ostype": os_type,
                            "ssl": ssl_data,
                            "last_detected": datetime.strftime(datetime.now(), "%Y-%m-%d:%H-%M-%S")
                        }
                    else:                    
                        results[domain_name]["ips"][i_ip]["ports"][int(port_id)] = {
                            "status": "open",
                            "protocol": "tcp",
                            "service": service,
                            "product": product,
                            "version": version,
                            "extrainfo": extra_info,
                            "ostype": os_type,
                            "last_detected": datetime.strftime(datetime.now(), "%Y-%m-%d:%H-%M-%S")
                        }
            ip_scan_history[i_ip] = results[domain_name]["ips"][i_ip]
            print(f"Finished NMAP for {i_ip}")   

    # save tmp results
    with open(f'{tmp_reports}/results_{domain_name}.json', 'w') as outfile:
        json.dump(results, outfile, indent=4)


print("Writing short results to file")
with open(f'reports/shoet_report_{datetime.strftime(datetime.now(), "%Y_%m_%d-%H_%M_%S")}.json', 'w') as outfile:
    json.dump(results, outfile, indent=4)

# Run Nmap scanning woth scripts
print("\n\n")
print("-"*100)
print("Start NMAP scanning with scripts for open ports")

NMAP_SCRIPTS_MAPPING = {
    "http": ["http-headers", "http-methods", "http-title", "http-trace", "http-robots.txt"],
    "https": ["http-headers", "http-methods", "http-title", "http-trace", "http-robots.txt", "ssl-enum-ciphers", "ssl-cert", "ssl-date"],
    "ftp": ["ftp-anon", "ftp-bounce", "ftp-proftpd-backdoor", "ftp-vsftpd-backdoor", "ftp-vuln-cve2010-4221", "ftp-vuln-cve2015-3306", "ftp-vuln", "ftp-libopie", "ftp-syst", "ftp-bad-serv", "ftp-brute", "ftp-enum", "ftp-syst", "ftp-libopie", "ftp-bad-serv", "ftp-brute", "ftp-enum"],
    "ssh": ["ssh-auth-methods", "ssh-hostkey", "ssh-run", "sshv1", "ssh2-enum-algos"],
    "smtp": ["smtp-commands", "smtp-enum-users", "smtp-ntlm-info", "smtp-open-relay", "smtp-vuln-cve2010-4344"],
    "pop3": ["pop3-capabilities", "pop3-ntlm-info"],
    "imap": ["imap-capabilities", "imap-ntlm-info"],
    "mssql": ["mssql-info", "mssql-ntlm-info", "mssql-databases", "mssql-config", "mssql-xp-cmdshell"],
    "mysql": ["mysql-audit", "mysql-databases", "mysql-dump-hashes", "mysql-empty-password", "mysql-enum"],
    "rdp": ["rdp-enum-encryption", "rdp-vuln-ms12-020"],
    "vnc": ["vnc-auth", "vnc-info"],
    "rpc": ["rpcinfo", "nfs-ls", "nfs-showmount", "nfs-statfs", "nfs-export"],
    "smb": ["smb-enum-domains", "smb-enum-groups", "smb-enum-processes", "smb-enum-sessions", "smb-enum-shares", "smb-enum-users", "smb-ls", "smb-mbenum", "smb-os-discovery", "smb-print-text", "smb-psexec", "smb-security-mode", "smb-server-stats"],
    "snmp": ["snmp-brute", "snmp-info", "snmp-netstat", "snmp-processes", "snmp-sysdescr", "snmp-win32-services", "snmp-win32-shares", "snmp-win32-software", "snmp-win32-users", "snmp-win32-vuln"],
    "dns": ["dns-service-discovery", "dns-zone-transfer", "dns-update", "dns-recursion", "dns-random-srcport", "dns-random-txid", "dns-nsid", "dns-nsec-enum", "dns-axfr-enum", "dns-srv-enum", "dns-nsec3-enum", "dns-rrsig-enum", "dns-nsid-enum"],
    "ntp": ["ntp-info", "ntp-monlist", "ntp-ntlm-info", "ntp-ops", "ntp-version"],
    "tftp": ["tftp-enum"],
    "http-proxy": ["http-proxy-brute", "http-proxy-open"],
    "socks": ["socks-auth", "socks-open-proxy"],
    "sip": ["sip-methods", "sip-enum-users", "sip-enum-registrations", "sip-enum-servers", "sip-enum-auth-username", "sip-enum-extension", "sip-enum-uri"],
    "smtps": ["smtp-commands", "smtp-enum-users", "smtp-ntlm-info", "smtp-open-relay", "smtp-vuln-cve2010-4344"],
    "pop3s": ["pop3-capabilities", "pop3-ntlm-info"],
    "imaps": ["imap-capabilities", "imap-ntlm-info"],
    "vnc-tls": ["vnc-auth", "vnc-info"],
    "ms-sql-s": ["mssql-info", "mssql-ntlm-info", "mssql-databases", "mssql-config", "mssql-xp-cmdshell"],
    "mysqls": ["mysql-audit", "mysql-databases", "mysql-dump-hashes", "mysql-empty-password", "mysql-enum"],
    "rdps": ["rdp-enum-encryption", "rdp-vuln-ms12-020"],
    "smb-tls": ["smb-enum-domains", "smb-enum-groups", "smb-enum-processes", "smb-enum-sessions", "smb-enum-shares", "smb-enum-users", "smb-ls", "smb-mbenum", "smb-os-discovery", "smb-print-text", "smb-psexec", "smb-security-mode", "smb-server-stats"],
    "snmps": ["snmp-brute", "snmp-info", "snmp-netstat", "snmp-processes", "snmp-sysdescr", "snmp-win32-services", "snmp-win32-shares", "snmp-win32-software", "snmp-win32-users", "snmp-win32-vuln"],
    "dnss": ["dns-service-discovery", "dns-zone-transfer", "dns-update", "dns-recursion", "dns-random-srcport", "dns-random-txid", "dns-nsid", "dns-nsec-enum", "dns-axfr-enum", "dns-srv-enum", "dns-nsec3-enum", "dns-rrsig-enum", "dns-nsid-enum"],
    "ntps": ["ntp-info", "ntp-monlist", "ntp-ntlm-info", "ntp-ops", "ntp-version"],
    "tftps": ["tftp-enum"],
    "http-proxys": ["http-proxy-brute", "http-proxy-open"],
    "sockss": ["socks-auth", "socks-open-proxy"],
    "rpcs": ["rpcinfo", "nfs-ls", "nfs-showmount", "nfs-statfs", "nfs-export"],
    "sips": ["sip-methods", "sip-enum-users", "sip-enum-registrations", "sip-enum-servers", "sip-enum-auth-username", "sip-enum-extension", "sip-enum-uri"]
}

ip_scan_history = {}

for domain_name in results:
    for i_ip in results[domain_name]["ips"]:
        if results[domain_name]["ips"][i_ip]["status"] == "open":
            open_ports = ','.join(str(port) for port in results[domain_name]["ips"][i_ip]["ports"])
            print(f"DEBUG: Open ports for {i_ip}: {open_ports}")
            print(f"Running NMAP with scripts for {i_ip}")
            for port in results[domain_name]["ips"][i_ip]["ports"]:
                if results[domain_name]["ips"][i_ip]["ports"][port]["status"] == "open":
                    if "ssl" in results[domain_name]["ips"][i_ip]["ports"][port]:
                        service = results[domain_name]["ips"][i_ip]["ports"][port]["service"] + "s"
                    else:
                        service = results[domain_name]["ips"][i_ip]["ports"][port]["service"]
                    
                    if service in NMAP_SCRIPTS_MAPPING:
                        scripts = ','.join(NMAP_SCRIPTS_MAPPING[service])
                        print(f"Running NMAP scripts for {i_ip}:{port}")
                        nmap_cmd = f"nmap -sC -sV -Pn -T3 -p{port} --script vulners,{scripts} -oX reports/nmap/{i_ip}/{i_ip}-{port}.xml {i_ip}"
                        print(f"DEBUG: Running Nmap command: {nmap_cmd}")
                        os.system(nmap_cmd)
                        print(f"Finished NMAP scripts for {i_ip}:{port}")
                    else:
                        print(f"No NMAP scripts for {service}. Skipping...")
            ip_scan_history[i_ip] = results[domain_name]["ips"][i_ip]
            print(f"Finished NMAP with scripts for {i_ip}")

print("Finished NMAP scanning with scripts")

# WEB HTTP Subdomain enumeration by dirb 
print("\n\n")
print("-"*100)
print("Start WEB HTTP Subdomain enumeration by dirb")

if not os.path.exists("reports/web/dirb"):
    print("Creating `reports/web/dirb` directory")
    os.makedirs("reports/web/dirb")

for domain_name in results:
    ips = results[domain_name]["ips"]
    for i_ip in ips:
        if results[domain_name]["ips"][i_ip]["status"] == "open":
            open_ports = ','.join(str(port) for port in results[domain_name]["ips"][i_ip]["ports"])
            print(f"DEBUG: Open ports for {i_ip}: {open_ports}")
            print(f"Running WEB HTTP Subdomain enumeration by dirb for {i_ip}")
            for port in results[domain_name]["ips"][i_ip]["ports"]:
                if results[domain_name]["ips"][i_ip]["ports"][port]["service"] == "http":
                    if results[domain_name]["ips"][i_ip]["ports"][port]["status"] == "open":
                        if "ssl" in results[domain_name]["ips"][i_ip]["ports"][port]:
                            print(f"Running dirb for {i_ip}:{port}")
                            dirb_cmd = f"dirb https://{i_ip}:{port} -o reports/web/dirb/{i_ip}-{port}.txt"
                            print(f"DEBUG: Running dirb command: {dirb_cmd}")
                            os.system(dirb_cmd)
                            print(f"Finished dirb for {i_ip}:{port}")
                        else:
                            print(f"Running dirb for {i_ip}:{port}")
                            dirb_cmd = f"dirb http://{i_ip}:{port} -o reports/web/dirb/{i_ip}-{port}.txt"
                            print(f"DEBUG: Running dirb command: {dirb_cmd}")
                            os.system(dirb_cmd)
                            print(f"Finished dirb for {i_ip}:{port}")

print("Finished WEB HTTP Subdomain enumeration by dirb")
sys.exit(0)
# Run WEB HTTP/HTTPS scanning by whatweb, nikto, wafw00f, SSLyze, zap-cli
print("\n\n")
print("-"*100)
print("Start WEB HTTP/HTTPS scanning")

if not os.path.exists("reports/web"):
    print("Creating `reports/web` directory")
    os.makedirs("reports/web")
if not os.path.exists("reports/web/whatweb"):
    print("Creating `reports/web/whatweb` directory")
    os.makedirs("reports/web/whatweb")
if not os.path.exists("reports/web/nikto"):
    print("Creating `reports/web/nikto` directory")
    os.makedirs("reports/web/nikto")
if not os.path.exists("reports/web/wafw00f"):
    print("Creating `reports/web/wafw00f` directory")
    os.makedirs("reports/web/wafw00f")
if not os.path.exists("reports/web/sslyze"):
    print("Creating `reports/web/sslyze` directory")
    os.makedirs("reports/web/sslyze")
if not os.path.exists("reports/web/zap-cli"):
    print("Creating `reports/web/zap-cli` directory")
    os.makedirs("reports/web/zap-cli")

for domain_name in results:
    ips = results[domain_name]["ips"]
    for i_ip in ips:
        if results[domain_name]["ips"][i_ip]["status"] == "open":
            open_ports = ','.join(str(port) for port in results[domain_name]["ips"][i_ip]["ports"])
            print(f"DEBUG: Open ports for {i_ip}: {open_ports}")
            print(f"Running WEB HTTP/HTTPS scanning for {i_ip}")
            for port in results[domain_name]["ips"][i_ip]["ports"]:
                if results[domain_name]["ips"][i_ip]["ports"][port]["status"] == "open":
                    if results[domain_name]["ips"][i_ip]["ports"][port]["service"] == "http":
                        # if ssl is enabled switch scan to https
                        if "ssl" in results[domain_name]["ips"][i_ip]["ports"][port]:
                            print(f"Running WhatWeb for {i_ip}:{port}")
                            whatweb_cmd = f"whatweb -a 3 -v -t 10 -o reports/web/whatweb/{i_ip}-{port}.json https://{i_ip}:{port}"
                            print(f"DEBUG: Running WhatWeb command: {whatweb_cmd}")
                            os.system(whatweb_cmd)
                            print(f"Finished WhatWeb for {i_ip}:{port}")

                            print(f"Running Nikto for {i_ip}:{port}")
                            nikto_cmd = f"nikto -h https://{i_ip}:{port} -o reports/web/nikto/{i_ip}-{port}.json"
                            print(f"DEBUG: Running Nikto command: {nikto_cmd}")
                            os.system(nikto_cmd)
                            print(f"Finished Nikto for {i_ip}:{port}")

                            print(f"Running WAFW00F for {i_ip}:{port}")
                            wafw00f_cmd = f"wafw00f https://{i_ip}:{port} -o reports/web/wafw00f/{i_ip}-{port}.json"
                            print(f"DEBUG: Running WAFW00F command: {wafw00f_cmd}")
                            os.system(wafw00f_cmd)
                            print(f"Finished WAFW00F for {i_ip}:{port}")

                            print(f"Running SSLyze for {i_ip}:{port}")
                            sslyze_cmd = f"sslyze --regular https://{i_ip}:{port} -o reports/web/sslyze/{i_ip}-{port}.json"
                            print(f"DEBUG: Running SSLyze command: {sslyze_cmd}")
                            os.system(sslyze_cmd)
                            print(f"Finished SSLyze for {i_ip}:{port}")

                            print(f"Running ZAP-CLI for {i_ip}:{port}")
                            zap_cmd = f"zap-cli quick-scan --spider --self-contained --quick-scan --start-options '-config api.disablekey=true' --output reports/web/zap-cli/{i_ip}-{port}.json https://{i_ip}:{port}"
                            print(f"DEBUG: Running ZAP-CLI command: {zap_cmd}")
                            os.system(zap_cmd)
                            print(f"Finished ZAP-CLI for {i_ip}:{port}")
                        else:
                            print(f"Running WhatWeb for {i_ip}:{port}")
                            whatweb_cmd = f"whatweb -a 3 -v -t 10 -o reports/web/whatweb/{i_ip}-{port}.json http://{i_ip}:{port}"
                            print(f"DEBUG: Running WhatWeb command: {whatweb_cmd}")
                            os.system(whatweb_cmd)
                            print(f"Finished WhatWeb for {i_ip}:{port}")

                            print(f"Running Nikto for {i_ip}:{port}")
                            nikto_cmd = f"nikto -h http://{i_ip}:{port} -o reports/web/nikto/{i_ip}-{port}.json"
                            print(f"DEBUG: Running Nikto command: {nikto_cmd}")
                            os.system(nikto_cmd)
                            print(f"Finished Nikto for {i_ip}:{port}")

                            print(f"Running WAFW00F for {i_ip}:{port}")
                            wafw00f_cmd = f"wafw00f http://{i_ip}:{port} -o reports/web/wafw00f/{i_ip}-{port}.json"
                            print(f"DEBUG: Running WAFW00F command: {wafw00f_cmd}")
                            os.system(wafw00f_cmd)
                            print(f"Finished WAFW00F for {i_ip}:{port}")

                            print(f"Running SSLyze for {i_ip}:{port}")
                            sslyze_cmd = f"sslyze --regular http://{i_ip}:{port} -o reports/web/sslyze/{i_ip}-{port}.json"
                            print(f"DEBUG: Running SSLyze command: {sslyze_cmd}")
