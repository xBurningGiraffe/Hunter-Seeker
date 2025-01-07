import threading
import time
import csv
import argparse
import requests
import socket
import random
import json
from queue import Queue
from wafw00f.main import WafW00F
import subprocess

# Define the ASCII Art Banner
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
    """
    Prints the ASCII banner in a random color and centers it.
    """
    colors = ["\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[95m", "\033[96m", "\033[97m"]
    color_end = "\033[0m"
    color = random.choice(colors)
    banner_lines = BANNER.splitlines()
    width = max(len(line) for line in banner_lines)
    centered_banner = "\n".join(line.center(width) for line in banner_lines)
    print(color + centered_banner + color_end)

def basic_enumeration(target):
    """
    Performs basic enumeration such as ping check, HTTP headers, and server banner.
    """
    result = {
        "Ping Reachable": "No",
        "HTTP Headers": "N/A",
        "Server Banner": "N/A"
    }
    try:
        # Ping check
        ping_cmd = ["ping", "-c", "1", target] if not target.replace(".", "").isdigit() else ["ping", "-c", "1", target]
        ping = subprocess.run(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if ping.returncode == 0:
            result["Ping Reachable"] = "Yes"

        # HTTP headers and server banner
        url = f"http://{target}"  # Use http by default, extend to https as needed
        response = requests.head(url, timeout=5)
        result["HTTP Headers"] = dict(response.headers)
        result["Server Banner"] = response.headers.get("Server", "N/A")
    except Exception as e:
        result["Ping Reachable"] = "Error"
        result["HTTP Headers"] = str(e)
    return result

def detect_waf_and_domains(target, results, rate_limit):
    """
    Detects if a WAF is present for a given target and performs basic enumeration.
    """
    try:
        # Reverse DNS Lookup for domains
        try:
            domain = socket.gethostbyaddr(target)[0]
        except socket.herror:
            domain = "Not Resolvable"

        # Basic Enumeration
        enumeration = basic_enumeration(target)

        # WAF Detection
        url = f"http://{target}"  # Change to https if necessary
        print(f"Scanning {target}...")
        waf_detector = WafW00F(target=url)
        waf_detector.identwaf()
        waf_results = waf_detector.get_detected_waf()

        results.append({
            "Target": target,
            "Domain/Subdomain": domain,
            "WAF Detected": "Yes" if waf_results else "No",
            "WAF Type": ", ".join(waf_results) if waf_results else "N/A",
            **enumeration
        })
    except Exception as e:
        results.append({
            "Target": target,
            "Domain/Subdomain": "Error" if "domain" not in locals() else domain,
            "WAF Detected": "Error",
            "WAF Type": str(e),
            "Ping Reachable": "Error",
            "HTTP Headers": "Error",
            "Server Banner": "Error"
        })
    finally:
        time.sleep(rate_limit)

def worker(queue, results, rate_limit):
    """
    Worker thread function to process targets from the queue.
    """
    while not queue.empty():
        target = queue.get()
        detect_waf_and_domains(target, results, rate_limit)
        queue.task_done()

def save_results(results, output_file, output_format):
    """
    Save results in the specified format: CSV, JSON, or TXT.
    """
    if output_format == "csv":
        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = results[0].keys()
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)
    elif output_format == "json":
        with open(output_file, 'w') as jsonfile:
            json.dump(results, jsonfile, indent=4)
    elif output_format == "txt":
        with open(output_file, 'w') as txtfile:
            for result in results:
                txtfile.write(str(result) + "\n")
    print(f"Results saved to {output_file} in {output_format.upper()} format.")

def main(target, output_file, output_format, threads, rate_limit):
    """
    Main function to manage target enumeration and WAF detection.
    """
    print_banner()

    # Parse input target
    if target.endswith(".txt"):  # File input
        with open(target, 'r') as file:
            targets = [line.strip() for line in file if line.strip()]
    else:  # Single IP or domain
        targets = [target]

    # Queue for targets
    queue = Queue()
    for t in targets:
        queue.put(t)

    # Results list
    results = []

    # Create threads
    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=worker, args=(queue, results, rate_limit))
        t.start()
        thread_list.append(t)

    # Wait for threads to finish
    for t in thread_list:
        t.join()

    # Save results
    save_results(results, output_file, output_format)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""
Hunter-Seeker: A tool for detecting Web Application Firewalls (WAFs) 
and associated domains for a list of targets (IPs/domains). 
Supports multithreading and rate limiting with flexible output formats.
        """,
        epilog="""
Example usage:
python hunter_seeker.py target.txt results.csv --output_format csv --threads 10 --rate_limit 0.5

Author: xBurningGiraffe
        """
    )
    parser.add_argument(
        "target",
        help="Single IP, domain, or path to a file containing multiple targets (one per line)."
    )
    parser.add_argument(
        "output_file",
        help="Path to save the output results."
    )
    parser.add_argument(
        "--output_format",
        choices=["csv", "json", "txt"],
        default="csv",
        help="Specify the output format: csv, json, or txt (default: csv)."
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=5,
        help="Number of threads to use for scanning (default: 5)."
    )
    parser.add_argument(
        "--rate_limit",
        type=float,
        default=1.0,
        help="Rate limit (in seconds) between requests to avoid overloading (default: 1.0)."
    )

    args = parser.parse_args()
    main(args.target, args.output_file, args.output_format, args.threads, args.rate_limit)
