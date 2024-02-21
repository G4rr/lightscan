#!/usr/bin/env python3

import os
import logging
import ipaddress
import time
import inspect
import xml.etree.ElementTree as ET
from datetime import datetime

import settings as s

l = logging.getLogger(__name__)

NMAP_SCRIPTS_MAPPING = {
    "http": ["http-headers", "http-methods", "http-title", "http-trace", "http-robots.txt", "ssl-enum-ciphers", "ssl-cert", "ssl-date"],
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
}


def run_nmap_general(ip: str, results: dict, nmap_scripts: list = []) -> dict:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        l.error(f"ERROR: {ip} is not a valid IP address format. Skipping...")
        return
    
    open_ports = ",".join([str(port) for port in results])
    
    nmap_cmd = f"nmap -sV -sC -Pn -T4 -p{open_ports} -oX reports/nmap/{ip}/{ip}.xml {ip}"
    print(f"NMAP DEBUG: Running Nmap command: {nmap_cmd}")
    l.info(f"NMAP DEBUG: Running Nmap command: {nmap_cmd}")
    os.system(nmap_cmd)
    
    # Parse NMAP XML report
    
    print(f"NMAP DEBUG: Parsing NMAP XML report for {ip}")
    print(f"NMAP DEBUG: NMAP XML report: {open(f'reports/nmap/{ip}/{ip}.xml', 'r').read()}")
    with open(f"reports/nmap/{ip}/{ip}.xml", 'r') as file:
        nmap_report = file.read()

    root = ET.fromstring(nmap_report)
    for host in root.findall('host'):
        l.info(f"NMAP DEBUG: Host: {host}")
        for port in host.findall('ports/port'):
            port_number = str(port.get('portid'))
            service = port.find('service').get('name') if port.find('service').get('name') else None
            product = port.find('service').get('product') if port.find('service').get('product') else None
            version = port.find('service').get('version') if port.find('service').get('version') else None
            extra_info = port.find('service').get('extrainfo') if port.find('service').get('extrainfo') else None
            os_type = port.find('service').get('ostype') if port.find('service').get('ostype') else None

            ssl = port.find('script[@id="ssl-cert"]')
            ssl_data = {}
            if ssl:
                print(f"SSL Cert: {ssl.get('output')}")
                l.info(f"SSL Cert: {ssl.get('output')}")
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
                results[port_number]["tcp"] = {
                    "service": service,
                    "product": product,
                    "version": version,
                    "extrainfo": extra_info,
                    "ostype": os_type,
                    "ssl": ssl_data,
                    "last_detected": datetime.strftime(datetime.now(), "%Y-%m-%d:%H-%M-%S")
                }
            else:                    
                results[port_number]["tcp"] = {
                    "service": service,
                    "product": product,
                    "version": version,
                    "extrainfo": extra_info,
                    "ostype": os_type,
                    "last_detected": datetime.strftime(datetime.now(), "%Y-%m-%d:%H-%M-%S")
                }
        print(f"NMAP DEBUG: NMAP results for {ip}: {results}")
        l.info(f"NMAP DEBUG: NMAP results for {ip}: {results}")
    return results

def run_nmap_scripts(ip: str, port: str, service: str, nmap_scripts: str = None) -> dict:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        l.error(f"ERROR: {ip} is not a valid IP address format. Skipping...")
        print(f"ERROR: {ip} is not a valid IP address format. Skipping...")
        return
    
    if nmap_scripts:
        scripts = nmap_scripts
    else:
        if service == "tcpwrapped":
            return
        if service in NMAP_SCRIPTS_MAPPING:
            scripts = "vulners,"+",".join(NMAP_SCRIPTS_MAPPING[service])
        else:
            scripts = "vulners"

    print(f"Running NMAP scripts for {ip}:{port} ({service})")
    l.info(f"Running NMAP scripts for {ip}:{port} ({service})")
    nmap_cmd = f"nmap -sC -sV -Pn -T3 -p{port} --script {scripts} -oX reports/nmap/{ip}/{ip}-{port}-scripts.xml {ip}"
    print(f"NMAP DEBUG: Running Nmap command: {nmap_cmd}")
    l.info(f"NMAP DEBUG: Running Nmap command: {nmap_cmd}")
    os.system(nmap_cmd)
    print(f"Finished NMAP scripts for {ip}:{port} ({service})")
    l.info(f"Finished NMAP scripts for {ip}:{port} ({service})")
    
    return
    


    
