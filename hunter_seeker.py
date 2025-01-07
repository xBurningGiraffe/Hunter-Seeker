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
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ASCII Art Banner
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

def create_session():
    """
    Creates a session with retry logic for HTTP/HTTPS requests.
    """
    session = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

def get_protocol(target, timeout):
    """
    Determines if the target supports HTTPS. Falls back to HTTP if HTTPS fails.
    """
    session = create_session()
    try:
        response = session.head(f"https://{target}", timeout=timeout)
        if response.status_code < 400:
            return "https"
    except requests.RequestException:
        print(f"Warning: HTTPS failed for {target}. Falling back to HTTP.")
        return "http"
    return "https"

def ping_target(target):
    """
    Attempts to ping a target and returns True if reachable, False otherwise.
    """
    try:
        cmd = ["ping", "-c", "1", target]
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0
    except Exception:
        return False

def detect_waf_and_domains(target, results, rate_limit, timeout):
    """
    Detects if a WAF is present for a given target and performs basic enumeration.
    Uses the specified timeout for HTTP/HTTPS requests.
    """
    try:
        protocol = get_protocol(target, timeout)
        url = f"{protocol}://{target}"
        print(f"Scanning {url}...")

        # DNS Lookup (reverse for IPs, forward for domains)
        try:
            domain = socket.gethostbyaddr(target)[0]  # Reverse DNS lookup
            print(f"Reverse DNS resolved {target} to {domain}.")
        except socket.herror:
            try:
                domain = socket.gethostbyname(target)  # Forward DNS lookup
                print(f"Forward DNS resolved {target} to {domain}.")
            except socket.gaierror:
                domain = None
                print(f"Unable to resolve target {target}.")

        # Log the timeout value
        print(f"Using timeout: {timeout} seconds for WAF detection.")

        # WAF Detection
        waf_detector = WAFW00F(target=url, timeout=timeout)
        waf_detector.identwaf()
        detected_wafs = waf_detector.knowledge['wafname']

        # Append results, even if an error is encountered later
        results.append({
            "Target": target,
            "Protocol": protocol,
            "Domain/Subdomain": domain if domain else "Not Resolvable",
            "Ping Reachable": "Yes" if ping_target(target) else "No",
            "WAF Detected": "Yes" if detected_wafs else "No",
            "WAF Type": ", ".join(detected_wafs) if detected_wafs else "N/A"
        })

    except requests.exceptions.ReadTimeout:
         # Suppress timeout error if WAF was already detected
        if any(r["Target"] == target and r["WAF Detected"] == "Yes" for r in results):
            print(f"Read Timeout for {target}, but WAF detection succeeded.")
        else:
            print(f"Read Timeout: The server at {target} did not respond in time.")
            results.append({
                "Target": target,
                "Protocol": protocol,
                "Domain/Subdomain": "N/A",
                "Ping Reachable": "No",
                "WAF Detected": "Error",
                "WAF Type": "Read Timeout"
            })
    except requests.exceptions.ConnectionError as e:
        print(f"Connection Error for {target}: {e}")
        results.append({
            "Target": target,
            "Protocol": protocol,
            "Domain/Subdomain": "N/A",
            "Ping Reachable": "No",
            "WAF Detected": "Error",
            "WAF Type": "Connection Error"
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




def worker(queue, results, rate_limit, timeout):
    while not queue.empty():
        target = queue.get()
        detect_waf_and_domains(target, results, rate_limit, timeout)
        queue.task_done()

def save_results(results, output_file):
    """
    Save results based on the file extension in the output_file argument.
    Supports CSV, JSON, and TXT. JSON output is pretty-printed.
    """
    extension = output_file.split('.')[-1].lower()

    if extension == "csv":
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
    elif extension == "json":
        with open(output_file, 'w') as jsonfile:
            json.dump(results, jsonfile, indent=4)
    elif extension == "txt":
        with open(output_file, 'w') as txtfile:
            for result in results:
                txtfile.write(str(result) + "\n")
    else:
        raise ValueError(f"Unsupported file format: {extension}")

    print(f"Results saved to {output_file} in {extension.upper()} format.")

def main(args):
    print_banner()

    # Set default output file if none is provided
    output_file = args.output_file if args.output_file else "results.csv"

    targets = []
    if args.target_file:
        with open(args.target_file, 'r') as file:
            targets = [line.strip() for line in file if line.strip()]
    elif args.target:
        targets = [args.target]

    if not targets:
        print("Error: No targets specified. Use --target or --target_file.")
        sys.exit(1)

    queue = Queue()
    for target in targets:
        queue.put(target)

    results = []
    threads = [
        threading.Thread(target=worker, args=(queue, results, args.rate_limit, args.timeout))
        for _ in range(args.threads)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    save_results(results, output_file)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        parser = CustomArgumentParser(description="Hunter-Seeker: Detect WAFs and enumerate targets.")
        parser.print_help()
        sys.exit(1)

    parser = CustomArgumentParser(description="Hunter-Seeker: Detect WAFs and enumerate targets.")
    parser.add_argument("-t", "--target", help="Single IP or domain to scan.")
    parser.add_argument("-f", "--target_file", help="Path to a file containing multiple targets (one per line).")
    parser.add_argument("-o", "--output_file", help="Path to save the output results (extension determines format: .csv, .json, .txt). Defaults to 'results.csv'")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads to use (default: 5).")
    parser.add_argument("--rate_limit", type=float, default=1.0, help="Rate limit (seconds) between requests (default: 1.0).")
    parser.add_argument("--timeout", type=int, default=7, help="Timeout (in seconds) for HTTP/HTTPS requests (default: 7 seconds).")

    args = parser.parse_args()

    if not args.target and not args.target_file:
        print("Error: Specify either --target or --target_file.")
        parser.print_help()
        sys.exit(1)

    main(args)
