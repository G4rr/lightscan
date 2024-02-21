#!/usr/bin/env python3

import os
import logging
import ipaddress
import time
import inspect

import settings as s

l = logging.getLogger(__name__)

def dig_short(domain: str, dns_type: str, dns_server: str = s.DNS_SERVER):
    cmd = f"dig @{dns_server} {domain} {dns_type} +short"
    l.debug(f"Running: {cmd}")
    result = os.popen(cmd).read().strip()
    l.debug(f"Result: {result}")
    return result

def digup(domain: str, dns_types: list = s.DNS_TYPES, delay: float = .1) -> dict:
    results = {}
    for dns_type in dns_types:
        dig_response = dig_short(domain, dns_type)
        for line in dig_response.split("\n"):
            if line:
                results[dns_type] = []
                if dns_type == "A" or dns_type == "AAAA":
                    # check is the line vaild IP address
                    try:
                        ipaddress.ip_address(line)
                        results[dns_type].append(line)
                    except ValueError:
                        print(f"Warning: {line} as A/AAAA of {domain} is not a valid IP address format. Skipping...")
                        continue
                else:
                    results[dns_type].append(line)
            else:
                pass
        time.sleep(delay)
    return results

