#!/usr/bin/env python3

import threading
import time
import csv
import argparse
import requests
import socket
import random
import json
from queue import Queue
from wafw00f.main import WAFW00F
import subprocess
import sys

BANNER = """
██   ██ ██    ██ ███    ██ ████████ ███████ ██████        ███████ ███████ ███████ ██   ██ ███████ ██████  
██   ██ ██    ██ ████   ██    ██    ██      ██   ██       ██      ██      ██      ██  ██  ██      ██   ██ 
███████ ██    ██ ██ ██  ██    ██    █████   ██████  █████ ███████ █████   █████   █████   █████   ██████  
██   ██ ██    ██ ██  ██ ██    ██    ██      ██   ██            ██ ██      ██      ██  ██  ██      ██   ██ 
██   ██  ██████  ██   ████    ██    ███████ ██   ██       ███████ ███████ ███████ ██   ██ ███████ ██   ██

    Created By: xBurningGiraffe
    https://github.com/xBurningGiraffe
"""

def print_banner():
    colors = ["\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[95m", "\033[96m", "\033[97m"]
    print(random.choice(colors) + BANNER + "\033[0m")

class CustomArgumentParser(argparse.ArgumentParser):
    def print_help(self):
        print_banner()
        super().print_help()

def ping_target(target):
    try:
        cmd = ["ping", "-c", "1", target]
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0
    except Exception:
        return False

def get_protocol(target):
    """
    Determines if the target supports HTTPS. Falls back to HTTP if HTTPS fails.
    """
    try:
        # Test HTTPS connection
        response = requests.head(f"https://{target}", timeout=5)
        if response.status_code < 400:
            return "https"
    except requests.RequestException:
        pass

    # Default to HTTP if HTTPS fails
    return "http"

def detect_waf_and_domains(target, results, rate_limit):
    """
    Detects if a WAF is present for a given target and performs basic enumeration.
    Handles HTTP/HTTPS determination dynamically.
    """
    try:
        # Determine if the target supports HTTPS or fallback to HTTP
        protocol = get_protocol(target)
        url = f"{protocol}://{target}"  # Construct URL with the appropriate protocol
        print(f"Scanning {url}...")

        # Reverse DNS Lookup
        try:
            domain = socket.gethostbyaddr(target)[0]
        except socket.herror:
            domain = "Not Resolvable"

        # Check if the target is reachable via ping
        is_reachable = ping_target(target)

        # WAF Detection
        waf_detector = WAFW00F(target=url)
        waf_detector.identwaf()
        detected_wafs = waf_detector.knowledge['wafname']

        # Append results
        results.append({
            "Target": target,
            "Protocol": protocol,
            "Domain/Subdomain": domain,
            "Ping Reachable": "Yes" if is_reachable else "No",
            "WAF Detected": "Yes" if detected_wafs else "No",
            "WAF Type": ", ".join(detected_wafs) if detected_wafs else "N/A"
        })

    except requests.exceptions.ConnectTimeout:
        print(f"Timeout: Unable to connect to {target} ({protocol})")
        results.append({
            "Target": target,
            "Protocol": protocol,
            "Domain/Subdomain": "N/A",
            "Ping Reachable": "No",
            "WAF Detected": "Error",
            "WAF Type": "Connection Timeout"
        })
    except requests.exceptions.ConnectionError as e:
        print(f"Connection Error for {target} ({protocol}): {e}")
        results.append({
            "Target": target,
            "Protocol": protocol,
            "Domain/Subdomain": "N/A",
            "Ping Reachable": "No",
            "WAF Detected": "Error",
            "WAF Type": "Connection Reset/Error"
        })
    except Exception as e:
        print(f"Something went wrong for {target}: {e}")
        results.append({
            "Target": target,
            "Protocol": protocol,
            "Domain/Subdomain": "Error",
            "Ping Reachable": "Error",
            "WAF Detected": "Error",
            "WAF Type": str(e)
        })
    finally:
        time.sleep(rate_limit)




def worker(queue, results, rate_limit):
    while not queue.empty():
        detect_waf_and_domains(queue.get(), results, rate_limit)
        queue.task_done()

def save_results(results, output_file, output_format):
    with open(output_file, 'w', newline='') as outfile:
        if output_format == "csv":
            writer = csv.DictWriter(outfile, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
        elif output_format == "json":
            json.dump(results, outfile, indent=4)
        else:
            for result in results:
                outfile.write(str(result) + "\n")
    print(f"Results saved to {output_file} in {output_format.upper()} format.")

def main(args):
    print_banner()
    targets = []
    if args.target_file:
        with open(args.target_file, 'r') as file:
            targets = [line.strip() for line in file if line.strip()]
    elif args.target:
        targets = [args.target]

    queue = Queue()
    for target in targets:
        queue.put(target)

    results = []
    threads = [threading.Thread(target=worker, args=(queue, results, args.rate_limit)) for _ in range(args.threads)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    save_results(results, args.output_file, args.output_format)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print_banner()
        parser = CustomArgumentParser(description="Hunter-Seeker: Detect WAFs and enumerate targets.", epilog="Example: python hunter_seeker.py --target example.com --output_file results.csv")
        parser.print_help()
        sys.exit(1)

    parser = CustomArgumentParser(description="Hunter-Seeker: Detect WAFs and enumerate targets.", epilog="Example: python hunter_seeker.py --target_file targets.txt --output_file results.json")
    parser.add_argument("-t", "--target", help="Single IP or domain to scan.")
    parser.add_argument("-f", "--target_file", help="Path to a file containing multiple targets (one per line).")
    parser.add_argument("-o", "--output_file", required=True, help="Path to save the output results.")
    parser.add_argument("--output_format", choices=["csv", "json", "txt"], default="csv", help="Output format: csv, json, or txt.")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads to use (default: 5).")
    parser.add_argument("--rate_limit", type=float, default=1.0, help="Rate limit (seconds) between requests (default: 1.0).")

    args = parser.parse_args()

    if not args.target and not args.target_file:
        print("Error: Specify either --target or --target_file.")
        parser.print_help()
        sys.exit(1)

    main(args)
