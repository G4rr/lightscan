#!/usr/bin/env python3

import os
import logging
import configparser

SCRIPT_NAME = "lightscan"
SCRIPT_DIRECTORY = os.path.dirname(os.path.realpath(__file__))

class ConfigLoader():

    def __init__(self, conf_file=os.path.join(SCRIPT_DIRECTORY, "main.conf")):
        if not os.path.exists(conf_file):
            print(f"Config file {conf_file} not found")
            exit(1)        
        self.conf_file = conf_file
        

    def get_configs(self):
        configParser = configparser.RawConfigParser()
        configParser.read_file(open(self.conf_file))
        return configParser

def set_logging_format(level, logfile=None, filemode="w"):
    params = {
        "format": "[PID:%(process)d] [%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s",
        "level": level,
        "datefmt": "%d-%m-%Y %H:%M:%S"
    }
    
    if logfile:
        params.update({
            "filemode": filemode,
            "filename": logfile
        })

    logging.basicConfig(**params)


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

config = ConfigLoader().get_configs()

DNS_SERVER = config.get("local", "dns-server") if config.has_option("local", "dns-server") else "8.8.8.8"
DNS_TYPES = config.get("local", "dns-types") if config.has_option("local", "dns-types") else "A,AAAA,MX,NS,SOA,TXT"
DNS_TYPES = DNS_TYPES.split(",")

NMAP_SCANNER = eval(config.get("scanner", "nmap")) if config.has_option("scanner", "nmap") else False
NMAP_SCRIPTS_SCANNER = eval(config.get("scanner", "nmap-scripts")) if config.has_option("scanner", "nmap-scripts") else False
WHATWEB_SCANNER = eval(config.get("scanner", "whatweb")) if config.has_option("scanner", "whatweb") else False
NIKTO_SCANNER = eval(config.get("scanner", "nikto")) if config.has_option("scanner", "nikto") else False
FFUF_SCANNER = eval(config.get("scanner",  "ffuf")) if config.has_option("scanner", "ffuf") else False

PORTS_FILE = config.get("ports", "ports-file") if config.has_option("ports", "ports-file") else "ports/100.txt"

DIRECTORY_WORDLIST = config.get("wordlist", "directory") if config.has_option("wordlist", "directory") else "/usr/share/wordlists/dirb/common.txt"

TMP_DIRECTORY = SCRIPT_DIRECTORY+"/tmp"
TMP_REPORT_DIRECTORY = TMP_DIRECTORY+"/reports"

LOG_FILE_NAME = SCRIPT_NAME+".log"
LOG_DIRECTORY = SCRIPT_DIRECTORY+"/logs"
if not os.path.exists(LOG_DIRECTORY):
    print("Creating `logs` directory")
    os.makedirs(LOG_DIRECTORY)
LOG_FILEPATH = LOG_DIRECTORY+"/"+LOG_FILE_NAME
LOG_LEVEL = "DEBUG"

if not os.path.exists(SCRIPT_DIRECTORY+"reports"):
    os.makedirs(SCRIPT_DIRECTORY+"reports")
if not os.path.exists(SCRIPT_DIRECTORY+"reports/nmap"):
    os.makedirs(SCRIPT_DIRECTORY+"reports/nmap")
if not os.path.exists(SCRIPT_DIRECTORY+"reports/web"):
    os.makedirs(SCRIPT_DIRECTORY+"reports/web")
if not os.path.exists(SCRIPT_DIRECTORY+"reports/web/dirb"):
    os.makedirs(SCRIPT_DIRECTORY+"reports/web/dirb")
if not os.path.exists(SCRIPT_DIRECTORY+"reports/web/whatweb"):
    os.makedirs(SCRIPT_DIRECTORY+"reports/web/whatweb")
if not os.path.exists(SCRIPT_DIRECTORY+"reports/web/nikto"):
    os.makedirs(SCRIPT_DIRECTORY+"reports/web/nikto")
if not os.path.exists(SCRIPT_DIRECTORY+"reports/web/ffuf"):
    os.makedirs(SCRIPT_DIRECTORY+"reports/web/ffuf")
