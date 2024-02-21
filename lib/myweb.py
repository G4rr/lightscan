#!/usr/bin/env python3

import os
import logging
import time
import inspect
import threading

import settings as s

l = logging.getLogger(__name__)

def single_mydirb(host: str, port: int, subdir: str = "", wordlist: str = s.DIRECTORY_WORDLIST, delay: float = .1) -> dict:
    print(f"Running dirb for {host}:{port}/{subdir}")
    dirb_cmd = f"dirb http://{host}:{port}/{subdir} -o reports/web/dirb/{host}-{port}.txt -w {wordlist} -r {delay}"
    print(f"DEBUG: Running dirb command: {dirb_cmd}")
    os.system(dirb_cmd)

def mydirb_threading(host: str, data: dict, subdir: str = "", wordlist: str = s.DIRECTORY_WORDLIST, delay: float = .1) -> dict:
    http_services_count = (len([port for port in data["ports"] if data["ports"][port]["tcp"]["service"] == "http"]))
    thread_count = http_services_count
    threads = []
    for port in data["ports"]:
        if data["ports"][port]["tcp"]["service"] == "http" :
            t = threading.Thread(target=single_mydirb, args=(host, port, subdir, wordlist, delay))
            threads.append(t)
            print(f"DEBUG: Starting thread for {host}:{port}")
            t.start()
    for t in threads:
        t.join()


def mydirb(host: str, data: dict, subdir: str = "", wordlist: str = s.DIRECTORY_WORDLIST, delay: float = .1) -> dict:
    for port in data["ports"]:
        if data["ports"][port]["tcp"]["service"] == "http" :
            if "ssl" in data["ports"][port]["tcp"]:
                print(f"Running dirb for {host}:{port}")
                dirb_cmd = f"dirb https://{host}:{port}/{subdir} -o reports/web/dirb/{host}-{port}.txt -w {wordlist} -r {delay}"
                print(f"DEBUG: Running dirb command: {dirb_cmd}")
                os.system(dirb_cmd)
                print(f"Finished dirb for {host}:{port}/{subdir}")
            else:
                print(f"Running dirb for {host}:{port}/{subdir}")
                dirb_cmd = f"dirb http://{host}:{port}/{subdir} -o reports/web/dirb/{host}-{port}.txt -w {wordlist} -r {delay}"
                print(f"DEBUG: Running dirb command: {dirb_cmd}")
                os.system(dirb_cmd)
                print(f"Finished dirb for {host}:{port}")

def myffuf(host: str, data: dict, subdir: str = "", wordlist: str = s.DIRECTORY_WORDLIST) -> dict:
    for port in data["ports"]:
        if data["ports"][port]["tcp"]["service"] == "http":
            if "ssl" in data["ports"][port]["tcp"]:
                print(f"Running ffuf for {host}:{port}/{subdir}")
                ffuf_cmd = f"ffuf -w {wordlist} -u https://{host}:{port}/{subdir}/FUZZ -mc 200,204,300,302,307,308,401,403,405 -o reports/web/ffuf/{host}-{port}.json"
                print(f"DEBUG: Running ffuf command: {ffuf_cmd}")
                os.system(ffuf_cmd)
                print(f"Finished ffuf for {host}:{port}/{subdir}")
            else:
                print(f"Running ffuf for {host}:{port}/{subdir}")
                ffuf_cmd = f"ffuf -w {wordlist} -u http://{host}:{port}/{subdir}/FUZZ -mc 200,204,300,302,307,308,401,403,405 -o reports/web/ffuf/{host}-{port}.json"
                print(f"DEBUG: Running ffuf command: {ffuf_cmd}")
                os.system(ffuf_cmd)
                print(f"Finished ffuf for {host}:{port}")

def mywhatweb(host: str, data: dict, subdir: str = "") -> dict:
    for port in data["ports"]:
        if data["ports"][port]["tcp"]["service"] == "http":
            if "ssl" in data["ports"][port]["tcp"]:
                print(f"Running whatweb for {host}:{port}/{subdir}")
                whatweb_cmd = f"whatweb -v -a 3 -t 10 https://{host}:{port}/{subdir} > reports/web/whatweb/{host}-{port}.txt"
                print(f"DEBUG: Running whatweb command: {whatweb_cmd}")
                os.system(whatweb_cmd)
                print(f"Finished whatweb for {host}:{port}/{subdir}")
            else:
                print(f"Running whatweb for {host}:{port}/{subdir}")
                whatweb_cmd = f"whatweb -v -a 3 -t 10 http://{host}:{port}/{subdir} > reports/web/whatweb/{host}-{port}.txt"
                print(f"DEBUG: Running whatweb command: {whatweb_cmd}")
                os.system(whatweb_cmd)
                print(f"Finished whatweb for {host}:{port}")

def my_nikto(host: str, data: dict, subdir: str = "") -> dict:
    for port in data["ports"]:
        if data["ports"][port]["tcp"]["service"] == "http":
            print(f"Running nikto for {host}:{port}/{subdir}")
            nikto_cmd = f"nikto -h {host} -p {port} -Plugins ALL -o nikto_{host}-{port}.csv -Format csv"
            print(f"DEBUG: Running nikto command: {nikto_cmd}")
            os.system(nikto_cmd)
            print(f"Finished nikto for {host}:{port}")
            
            cmd = f"mv nikto_{host}-{port}.csv reports/web/nikto/"
            os.system(cmd)