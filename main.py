#!/usr/bin/env python3
# Purpose: A simple scanner

import os
import json
import sys
import time
import ipaddress
import argparse
import logging
import xml.etree.ElementTree as ET

import lib.mydig as mydig
import lib.mynmap as mynmap
import lib.myweb as myweb
import lib.mymasscan as mymasscan

import settings as s

from datetime import datetime
from scapy.all import *


l = logging.getLogger(__name__)

# check if the script is running as root
if os.geteuid() != 0:
    print("This script must be run as root")
    sys.exit(1)

results = {
}

SCAN_HISTORY = {}

def domain_scanner(domains: list, ports: list, init_file: str = None):
    if init_file:
        with open(init_file, "r") as file:
            results = json.load(file)
    else:
        results = {}
        # Make DNS resolving for each domain
        for domain in domains:
            domain = domain.strip()
            results[domain] = {
                "dns_info": {}
            }
            results[domain]["dns_info"] = mydig.digup(domain)    
            print(f"DEBUG: DNS results for {domain}: {results[domain]['dns_info']}")
            print("-" * 100)

        with open(f"domains.json", "w") as file:
            l.info(f"Writing results to domains.json")
            json.dump(results, file, indent=4)
        
        for domain in domains:
            domain = domain.strip()
            results[domain]["icmp_info"] = {}
            results[domain]["ips_info"] = {}

            if "A" in results[domain]["dns_info"]:
                for ip in results[domain]["dns_info"]["A"]:
                    if ip in SCAN_HISTORY:
                        results[domain]["ips_info"][ip] = SCAN_HISTORY[ip]
                        continue
                    os.system(f"mkdir -p reports/nmap/{ip}")

                    # Check if ICMP connection is possible
                    l.info(f"Checking if {ip} is up")
                    results[domain]["icmp_info"][ip] = mymasscan.icmp_check(ip, 3)
                    # Check if the IP is a cloudflare IP
                    l.info(f"Checking if {ip} is a Cloudflare IP")
                    results[domain]["ips_info"][ip] = mymasscan.cf_filter(ip)
                    # Run custom masscan for the IP
                    l.info(f"Running masscan for {ip}")
                    if results[domain]["ips_info"][ip]["status"] == "open":
                        port_detection_data = mymasscan.my_tcp_masscan(ip, ports)
                        if not port_detection_data:
                            results[domain]["ips_info"][ip]["ports"] = {}
                            continue
                        print(f"DEBUG: Port detection data for {ip}: {port_detection_data}")
                        # Run general nmap scanning
                        l.info(f"Running nmap for {ip}")
                        print(f"DEBUG: Running nmap for {port_detection_data}")
                        results[domain]["ips_info"][ip]["ports"] = mynmap.run_nmap_general(ip, port_detection_data)
                        # Add the IP to the SCAN_HISTORY
                        l.info(f"Adding {ip} to SCAN_HISTORY")
                        SCAN_HISTORY[ip] = results[domain]["ips_info"][ip]
                    else:
                        l.info(f"{ip} is not filtered. Skipping...")
                        continue
            else:
                l.info(f"No A records for {domain}. Skipping...")

        with open(f"new_results.json", "w") as file:
            l.info(f"Writing results to new_results.json")
            json.dump(results, file, indent=4)
    
        # Run nmap scripts for each IP/Service
        l.info(f"Running Nmap scripts for each IP/Service")
        for domain in results:
            for ip in results[domain]["ips_info"]:
                if results[domain]["ips_info"][ip]["status"] == "open":
                    _ip = ip.strip()
                    if "ports" not in results[domain]["ips_info"][ip]:
                        continue
                    for port in results[domain]["ips_info"][ip]["ports"]:
                        _port = port.strip()
                        tcp_service = results[domain]["ips_info"][ip]["ports"][port]["tcp"]["service"]
                        print(f"DEBUG: Running Nmap scripts for {_ip}:{_port} ({tcp_service})")
                        mynmap.run_nmap_scripts(_ip, _port, tcp_service)
                else:
                    l.info(f"{ip} is not filtered. Skipping...")
                    continue
    
    # Run Web scanning
    for domain in results:
        for ip in results[domain]["ips_info"]:
            if results[domain]["ips_info"][ip]["status"] == "open":
                if "ports" not in results[domain]["ips_info"][ip]:
                    continue
                _ip = ip.strip()
                #myweb.mywhatweb(ip, results[domain]["ips_info"][ip])
                myweb.myffuf(ip, results[domain]["ips_info"][ip])
                myweb.my_nikto(ip, results[domain]["ips_info"][ip])
            else:
                l.info(f"{ip} is not filtered. Skipping...")
                continue

    
def ip_scanner(ips: list, ports: list):
    results = {}
    for ip in ips:
        ip = ip.strip()
        os.system(f"mkdir -p reports/nmap/{ip}")
        results[ip] = {}
        results[ip]["icmp_info"] = {}
        results[ip]["ips_info"] = {}

        if ip in SCAN_HISTORY:
            results[ip]["ips_info"][ip] = SCAN_HISTORY[ip]
            continue

        # Check if ICMP connection is possible
        l.info(f"Checking if {ip} is up")
        print(f"DEBUG: Checking if {ip} is up")
        results[ip]["icmp_info"][ip] = mymasscan.icmp_check(ip, 3)
        # Check if the IP is a cloudflare IP
        l.info(f"Checking if {ip} is a Cloudflare IP")
        print(f"DEBUG: Checking if {ip} is a Cloudflare IP")
        results[ip]["ips_info"][ip] = mymasscan.cf_filter(ip)
        # Run custom masscan for the IP
        l.info(f"Running masscan for {ip}")
        print(f"DEBUG: Running masscan for {ip}")
        if results[ip]["ips_info"][ip]["status"] == "open":
            l.info(f"{ip} is open.")
            port_detection_data = mymasscan.my_tcp_masscan(ip, ports)
            if not port_detection_data:
                results[ip]["ips_info"][ip]["ports"] = {}
                l.info(f"No ports detected for {ip}. Skipping...")
                continue
            print(f"DEBUG: Port detection data for {ip}: {port_detection_data}")
            # Add the IP to the SCAN_HISTORY
            l.info(f"Adding {ip} to SCAN_HISTORY")
            SCAN_HISTORY[ip] = results[ip]["ips_info"][ip]
        else:
            l.info(f"{ip} is not filtered. Skipping...")
            continue

        if s.NMAP_SCANNER:
            # Run general nmap scanning
            l.info(f"Running nmap for {ip}")
            print(f"DEBUG: Running nmap for {port_detection_data}")
            results[ip]["ips_info"][ip]["ports"] = mynmap.run_nmap_general(ip, port_detection_data)
        else:
            print(f"DEBUG: Nmap scanning is disabled. Skipping...")

        with open(f"new_ips_results.json", "w") as file:
            l.info(f"Writing results to new_ips_results.json")
            json.dump(results, file, indent=4)
    
        # Run nmap scripts for each IP/Service
        if s.NMAP_SCRIPTS_SCANNER: 
            l.info(f"Running Nmap scripts for each IP/Service")
            for ip in results:
                for ip in results[ip]["ips_info"]:
                    if results[ip]["ips_info"][ip]["status"] == "open":
                        _ip = ip.strip()
                        if "ports" not in results[ip]["ips_info"][ip]:
                            continue
                        for port in results[ip]["ips_info"][ip]["ports"]:
                            _port = port.strip()
                            tcp_service = results[ip]["ips_info"][ip]["ports"][port]["tcp"]["service"]
                            print(f"DEBUG: Running Nmap scripts for {_ip}:{_port} ({tcp_service})")
                            mynmap.run_nmap_scripts(_ip, _port, tcp_service)
                    else:
                        l.info(f"{ip} is not filtered. Skipping...")
                        continue
        else:
            print(f"DEBUG: Nmap scripts scanning is disabled. Skipping...")
        
        # Run Web scanning
        if s.WHATWEB_SCANNER:
            for ip in results:
                if results[ip]["ips_info"][ip]["status"] == "open":
                    if "ports" not in results[ip]["ips_info"][ip]:
                        continue
                    _ip = ip.strip()
                    myweb.mywhatweb(ip, results[ip]["ips_info"][ip])
                else:
                    l.info(f"{ip} is not filtered. Skipping...")
                    continue
        else:
            print(f"DEBUG: WhatWeb scanning is disabled. Skipping...")
        
        if s.NIKTO_SCANNER:
            for ip in results:
                if results[ip]["ips_info"][ip]["status"] == "open":
                    if "ports" not in results[ip]["ips_info"][ip]:
                        continue
                    _ip = ip.strip()
                    myweb.my_nikto(ip, results[ip]["ips_info"][ip])
                else:
                    l.info(f"{ip} is not filtered. Skipping...")
                    continue
        else:
            print(f"DEBUG: Nikto scanning is disabled. Skipping...")

        if s.FFUF_SCANNER:
            for ip in results:
                if results[ip]["ips_info"][ip]["status"] == "open":
                    if "ports" not in results[ip]["ips_info"][ip]:
                        continue
                    _ip = ip.strip()
                    myweb.myffuf(ip, results[ip]["ips_info"][ip])
                else:
                    l.info(f"{ip} is not filtered. Skipping...")
                    continue
        else:
            print(f"DEBUG: FFUF scanning is disabled. Skipping...")
                        

def print_preview(host_list: list):
    print(f"""
Settings and configurations:
    - HOSTS: {host_list}
    - PORTS_FILE: {s.PORTS_FILE}
    - DNS_SERVER: {s.DNS_SERVER}
    - DNS_TYPES: {s.DNS_TYPES}
    - NMAP_SCANNER: {s.NMAP_SCANNER}
    - NMAP_SCRIPTS_SCANNER: {s.NMAP_SCRIPTS_SCANNER}
    - WHATWEB_SCANNER: {s.WHATWEB_SCANNER}
    - NIKTO_SCANNER: {s.NIKTO_SCANNER}
    - FFUF_SCANNER: {s.FFUF_SCANNER}
    - DIRECTORY_WORDLIST: {s.DIRECTORY_WORDLIST}
      """)


if __name__ == "__main__":
    s.set_logging_format(s.LOG_LEVEL, s.LOG_FILEPATH)
    # menu
    parser = argparse.ArgumentParser(description='A simple scanner')
    parser.add_argument('--port-file', help='Enter exist ports group name', type=str)
    parser.add_argument('--domain-file', help='Enter file with domains', type=str)
    parser.add_argument('--ip-file', help='Enter file with IPs', type=str)
    parser.add_argument('--init-report', help='Add earlier created report', type=str)

    args = parser.parse_args()
    if args.port_file:
        port_file = args.port_file
    else:
        port_file = s.PORTS_FILE
    
    if os.path.exists(port_file):
        with open(port_file, 'r') as file:
            ports = file.readlines()
    else:
        print(f"ERROR: {port_file} does not exist.")
        sys.exit(1)
    
        
    if args.domain_file:
        ip_file = None
        domain_file = args.domain_file
        if args.init_report:
            init_file = args.init_report
        else:
            init_file = None
        
        if os.path.exists(domain_file):
            with open(domain_file, 'r') as file:
                domains = file.readlines()
                domains = [domain.strip() for domain in domains]
        else:
            print(f"ERROR: {domain_file} does not exist.")
            sys.exit(1)
    elif args.ip_file:
        domain_file = None
        ip_file = args.ip_file     
        if os.path.exists(ip_file):
            with open(ip_file, 'r') as file:
                ips = file.readlines()  
                ips = [ip.strip() for ip in ips]
        else:
            print(f"ERROR: {ip_file} does not exist.")
            sys.exit(1)          
    else:
        print("ERROR: Please provide a domain file or an IP file.")
        sys.exit(1)

    if domain_file:
        print_preview(domains)
        domain_scanner(domains, ports, init_file)
    elif ip_file:
        print_preview(ips)
        ip_scanner(ips, ports)
    else:
        print("ERROR: Please provide a domain file or an IP file.")
        sys.exit(1)
