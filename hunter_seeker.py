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
    Defaults to HTTPS. Falls back to HTTP only if HTTPS fails.
    """
    try:
        # Test HTTPS connection
        response = requests.head(f"https://{target}", timeout=5)
        if response.status_code < 400:
            return "https"
    except requests.RequestException:
        print(f"Warning: HTTPS failed for {target}. Falling back to HTTP.")
        return "http"  # Fall back to HTTP if HTTPS fails

    return "https"  # Default to HTTPS


def detect_waf_and_domains(target, results, rate_limit):
    """
    Detects if a WAF is present for the given IP and any domains resolved via reverse DNS lookup.
    Tests both the IP address and the resolved domains.
    """
    try:
        # Resolve any domains associated with the IP
        try:
            resolved_domain = socket.gethostbyaddr(target)[0]
        except socket.herror:
            resolved_domain = None

        # Protocol determination (default to HTTPS, fallback to HTTP)
        def test_target(target_to_test):
            protocol = get_protocol(target_to_test)
            url = f"{protocol}://{target_to_test}"
            print(f"Scanning {url}...")

            waf_detector = WAFW00F(target=url)
            waf_detector.identwaf()
            detected_wafs = waf_detector.knowledge['wafname']
            return {
                "Target": target_to_test,
                "Protocol": protocol,
                "Ping Reachable": "Yes" if ping_target(target_to_test) else "No",
                "WAF Detected": "Yes" if detected_wafs else "No",
                "WAF Type": ", ".join(detected_wafs) if detected_wafs else "N/A"
            }

        # Test the IP address
        results.append(test_target(target))

        # If a domain was resolved, test it as well
        if resolved_domain:
            results.append(test_target(resolved_domain))

    except requests.exceptions.ConnectTimeout:
        print(f"Timeout: Unable to connect to {target}")
        results.append({
            "Target": target,
            "Protocol": "N/A",
            "Ping Reachable": "No",
            "WAF Detected": "Error",
            "WAF Type": "Connection Timeout"
        })
    except requests.exceptions.ConnectionError as e:
        print(f"Connection Error for {target}: {e}")
        results.append({
            "Target": target,
            "Protocol": "N/A",
            "Ping Reachable": "No",
            "WAF Detected": "Error",
            "WAF Type": "Connection Error"
        })
    except Exception as e:
        print(f"Something went wrong for {target}: {e}")
        results.append({
            "Target": target,
            "Protocol": "N/A",
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

def save_results(results, output_file):
    """
    Save results based on the file extension in the output_file argument.
    Supports CSV, JSON, and TXT. JSON output is pretty-printed.
    """
    extension = output_file.split('.')[-1].lower()  # Get file extension

    if extension == "csv":
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
    elif extension == "json":
        with open(output_file, 'w') as jsonfile:
            json.dump(results, jsonfile, indent=4)  # Pretty-print JSON
    elif extension == "txt":
        with open(output_file, 'w') as txtfile:
            for result in results:
                txtfile.write(str(result) + "\n")
    else:
        raise ValueError(f"Unsupported file format: {extension}")

    print(f"Results saved to {output_file} in {extension.upper()} format.")



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

    save_results(results, args.output_file)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print_banner()
        parser = CustomArgumentParser(description="Hunter-Seeker: Detect WAFs and enumerate targets.", epilog="Example: python hunter_seeker.py --target example.com --output_file results.csv")
        parser.print_help()
        sys.exit(1)

    parser = CustomArgumentParser(description="Hunter-Seeker: Detect WAFs and enumerate targets.")
    parser.add_argument("-t", "--target", help="Single IP or domain to scan.")
    parser.add_argument("-f", "--target_file", help="Path to a file containing multiple targets (one per line).")
    parser.add_argument("-o", "--output_file", required=True, help="Path to save the output results (extension determines format: .csv, .json, .txt).")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads to use (default: 5).")
    parser.add_argument("--rate_limit", type=float, default=1.0, help="Rate limit (seconds) between requests (default: 1.0).")


    args = parser.parse_args()

    if not args.target and not args.target_file:
        print("Error: Specify either --target or --target_file.")
        parser.print_help()
        sys.exit(1)

    main(args)
