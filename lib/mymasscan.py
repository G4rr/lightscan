#!/usr/bin/env python3

import os
import logging
import ipaddress
import time
import inspect
import threading
import socket
import signal
import subprocess
import threading

from datetime import datetime
from scapy.all import *

import settings as s

l = logging.getLogger(__name__)

def cf_filter(ip: str) -> dict:
    l.info(f"Checking if {ip} is a Cloudflare IP")
    if ipaddress.ip_address(ip):
        results = {
            "status": "open",
            "service": "exposed",
            "ports": {},
            "last_detected": datetime.strftime(datetime.now(), "%Y-%m-%d:%H-%M-%S")
        }
        if ipaddress.ip_address(ip).version == 4:
            results["version"] = "ipv4"
                # check if the IP is a cloudflare IP CIDRs
            for cf_ip4_cidr in s.CLOUDFLARE_IP4_FILTER:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(cf_ip4_cidr):
                    l.info(f"{ip} is a Cloudflare IP. Skipping...")
                    results["status"] = "filtered"
                    results["service"] = "cloudflare"
                    break
            # check if the IP is a private IP CIDRs
            for private_ip4_cidr in s.PRIVATE_IP4_FILTER:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(private_ip4_cidr):
                    l.info(f"{ip} is a private IP. Skipping...")
                    results["status"] = "filtered"
                    results["service"] = "private"
                    break
            return results
        elif ipaddress.ip_address(ip).version == 6:
            results["version"] = "ipv6"
            for cf_ip6_cidr in s.CLOUDFLARE_IP6_FILTER:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(cf_ip6_cidr):
                    l.info(f"{ip} is a Cloudflare IP. Skipping...")
                    results["status"] = "filtered"
                    results["service"] = "cloudflare"
                    break
            return results
    else:
        l.error(f"ERROR: {ip} is not a valid IP address format. Skipping...")
        results["status"] = "invalid"
        results["service"] = "invalid" 
        
        return results
    
def icmp_check(ip: str, packet_count: int = 1, timeout: float = 2) -> dict:
    results = {
        "status": "open",
        "last_detected": datetime.strftime(datetime.now(), "%Y-%m-%d:%H-%M-%S")
    }
    ip = IP(dst=ip)
    icmp = ICMP()
    resp = sr(ip/icmp, inter=0.5, retry=packet_count-1, timeout=timeout)
    #print(f"DEBUG: ICMP response: {resp}")
    if resp:
        l.info(f"{ip} icmp is up")
        return results
    else:
        l.info(f"{ip} icmp is down")
        results["status"] = "closed"
        return results


class NcRunner(threading.Thread):
    def __init__(self, command, timeout):
        threading.Thread.__init__(self)
        self.command = command
        self.timeout = timeout
        self.process = None
        self.result = None

    def run(self):
        start_time = time.time()
        self.process = subprocess.Popen(self.command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        while self.process.poll() is None:
            time.sleep(0.1)
            if time.time() - start_time > self.timeout:
                self.process.kill()
                self.result = "Opened"
                return
        self.result = self.process.communicate()

def run_nc_command(ip, port):
    l.info(f"Running nc command for {ip}:{port}")
    command = ['nc', '-v', ip, str(port)]
    nc_runner = NcRunner(command, 2)
    nc_runner.start()
    nc_runner.join()
    l.info(f"nc command result: {nc_runner.result}")
    return nc_runner.result
    
def my_tcp_masscan(ip: str, ports: list, tcp_flag: str = "A", timeout: float = .6) -> dict:
    results = {}
    _ip = IP(dst=ip)
    l.info(f"MyMasscan Scanning {ip} for open ports")
    for port in ports:
        #if isinstance(port, str):
        port = port.strip()
        int_port = int(port)
        l.info(f"MyMasscan Scanning {ip}:{port}")
        _tcp = TCP(sport=RandShort(), dport=int_port, flags=tcp_flag) # flags="A" for ACK scan
        pkt = _ip/_tcp
        resp = sr1(pkt, timeout=timeout)

        if resp:
            l.info(f"{ip}:{port} is open for ACK scan")
            result = run_nc_command(ip, port)
            if result == "Opened":
                l.info(f"{ip}:{port} is open for nc check")
                results[port] = {
                    "tcp": {}
                }
                results[port]["tcp"] = {"status": "open",
                                    "protocol": "tcp",                  
                                    "last_detected": datetime.strftime(datetime.now(), "%Y-%m-%d:%H-%M-%S")}
            else:
                l.info(f"{ip}:{port} is closed for nc check")
                continue
        else:
            l.info(f"{ip}:{port} is closed")
            continue
    return results

def my_udp_masscan(ip: str, ports: list, timeout: float = .5) -> dict:
    results = {}
    ip = IP(dst=ip)
    l.info(f"Scanning {ip} for open ports")
    for port in ports:
        port = int(port.strip())
        udp = UDP(sport=RandShort(), dport=port)
        pkt = ip/udp
        resp = sr1(pkt, timeout=timeout)

        if resp:
            l.info(f"{ip}:{port} is open")
            results[port]["udp"] = {"status": "open",
                                "protocol": "udp",                 
                                "last_detected": datetime.strftime(datetime.now(), "%Y-%m-%d:%H-%M-%S")}
        else:
            continue
    return results

# Scan multiple ports for one IP address
def multi_port_masscan(ip: str, ports: list, thread_count: int, tcp_flag: str = "A", timeout: float = .5) -> dict:
    ports_chunks = [ports[i:i + thread_count] for i in range(0, len(ports), thread_count)]
    threads = []
    results = {}
    for chunk in ports_chunks:
        t = threading.Thread(target=my_tcp_masscan, args=(ip, chunk, tcp_flag, timeout))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    for t in threads:
        results.update(t.results)
    return results

# Scan multiple IPs one port by one port
def multi_address_masscan(ips: list, ports: list, thread_count: int, tcp_flag: str = "A", timeout: float = .5) -> dict:
    threads = []
    results = {}
    for ip in ips:
        t = threading.Thread(target=multi_port_masscan, args=(ip, ports, thread_count, tcp_flag, timeout))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    for t in threads:
        results.update(t.results)
    return results